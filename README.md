# Kubernetes ServiceAccount Token 内部 API 认证 Demo

Pod 用 Projected ServiceAccount Token（audience=`internal-api`）作为 Bearer Token 调用内部 HTTPS API；服务端用 TokenReview 验证，结果按 `SHA-256(token)+audience+cluster` 做 30s 本地缓存，singleflight 合并并发 miss，认证后按 Namespace/ServiceAccount 做默认拒绝的授权。

图文说明（拓扑、安全链路时序图、1.18 实测结果）：[docs/overview.html](docs/overview.html)，在线预览：<https://htmlpreview.github.io/?https://github.com/Andrewmatilde/k8s-sa-token-auth-demo/blob/main/docs/overview.html>

依赖：标准库 + `k8s.io/client-go v0.18.19`（对应 1.18 集群，兼容 1.17 的 TokenReview v1 API）+ `golang.org/x/sync/singleflight`。

## 设计与认证流程

```
Client Pod ──HTTPS, Authorization: Bearer <projected SA JWT>──▶ Internal API
  Middleware
    1. 只接受一个 Authorization 头，格式为 "Bearer <base64url/. 字符>"，≤16KiB，否则 401
    2. key = SHA-256(token) + audience + cluster（不存明文）
    3. cache HIT 且未过期 → Identity
    4. MISS → singleflight(key) → TokenReview(spec.audiences=[服务端配置的 audience])
         · 独立超时（默认 3s），不受单个调用方取消影响
         · 检查 status.error 为空、authenticated=true、status.audiences 包含期望值
         · username 必须严格为 system:serviceaccount:<ns>:<name>
         · 只缓存成功结果；TTL 从发起 review 前计时
       singleflight 返回后再检查一次过期，过期则重试一次，仍过期则 503
    5. Identity{Cluster 来自 -cluster 参数, Namespace, ServiceAccount, Username, UID} 写入 context
  RequireAuthorization：StaticAuthorizer 精确匹配 (ns, sa, method, path)，否则 403
```

| 结果 | HTTP |
| --- | --- |
| 无 / 格式错误 / 无效 / audience 不匹配 / 非 SA 身份 | 401 |
| TokenReview 超时、API Server 不可用、返回 5xx | 503（fail closed，不缓存） |
| 认证通过但策略未允许 | 403 |

关键选择：

- **audience 只来自服务端配置**，客户端无法指定；Cluster 也只来自服务端 `-cluster`，`X-Namespace` 之类的头完全被忽略（有测试）。
- **认证缓存与授权分离**：缓存里只有 Identity，授权每次按当前策略实时计算，策略修改立即生效。
- **只缓存成功**：失败不缓存，避免把 API Server 抖动固化成拒绝，也绝不把异常当成功。代价是错误 token 每次都会 review（相同 token 的并发会被 singleflight 合并）；需要时可在前面加限流。
- **不解析 JWT payload 延长有效期**：TokenReview v1 不返回过期时间，所以用固定短 TTL，见下文的撤销延迟。
- **Client 每次请求重新读取 token 文件**：kubelet 通过 `..data` 符号链接原子替换来轮换 token，每次读都能拿到新值，文件很小、开销可忽略。只发往 https；可配置 host 白名单（`cmd/client` 默认只允许 `-url` 的 host）；跨 host 的重定向不跟随，防止 token 被带到别处。
- **FakeTokenReviewer** 只能通过 `-dev-fake-reviewer` 打开，检测到 `KUBERNETES_SERVICE_HOST`（即运行在 Pod 中）时拒绝启动；不提供 HTTP 明文模式。

代码布局：

```
cmd/server, cmd/client
internal/auth/
  identity.go    Identity、context、SA 用户名解析
  reviewer.go    TokenReviewer 接口、错误定义、共用校验、FakeTokenReviewer（仅开发/测试）
  kubernetes.go  KubernetesTokenReviewer（client-go AuthenticationV1）
  cache.go       并发安全的认证缓存
  middleware.go  Authenticator + net/http middleware
  authorizer.go  StaticAuthorizer + RequireAuthorization
  client.go      带 token 注入的 http.Client
  handler.go     Demo 路由
  auth_test.go   测试 + benchmark
deploy/kubernetes/demo.yaml
hack/gen-certs.sh
```

## 本地运行（无需 Kubernetes）

```bash
make run-dev          # 生成 certs/，以 fake reviewer 启动 https://localhost:8443
```

另开终端：

```bash
mkdir -p /tmp/tok && for t in worker controller other wrong-audience; do printf "dev-$t-token" > /tmp/tok/$t; done
bin/client -token-file /tmp/tok/worker     -ca-file certs/ca.crt -url https://localhost:8443/api/whoami          # 200
bin/client -token-file /tmp/tok/worker     -ca-file certs/ca.crt -url https://localhost:8443/api/jobs            # 200
bin/client -token-file /tmp/tok/worker     -ca-file certs/ca.crt -url https://localhost:8443/api/jobs -method POST -data '{"name":"a"}'  # 403
bin/client -token-file /tmp/tok/controller -ca-file certs/ca.crt -url https://localhost:8443/api/jobs -method POST -data '{"name":"a"}'  # 201
bin/client -token-file /tmp/tok/other      -ca-file certs/ca.crt -url https://localhost:8443/api/jobs            # 403
bin/client -token-file /tmp/tok/wrong-audience -ca-file certs/ca.crt -url https://localhost:8443/api/whoami      # 401
curl --cacert certs/ca.crt https://localhost:8443/healthz                                                         # ok
```

也可以用真实 TokenReview 在本地跑：`bin/server -kubeconfig <path> -cluster <id> -tls-cert ... -tls-key ...`。

## TLS 配置

- `hack/gen-certs.sh [dir] [额外 DNS SAN...]` 生成 demo CA 和服务端证书，SAN 已包含 `localhost`、`127.0.0.1` 以及 `internal-api.internal-api.svc[.cluster.local]`。生产环境请用公司 CA 或 cert-manager 签发。
- 服务端：`-tls-cert/-tls-key`，最低 TLS 1.2，不支持明文。
- 客户端：`-ca-file` 指定信任的 CA；不提供跳过证书校验的选项。

## 真实 Kubernetes 部署

前提：**kube-apiserver 必须启用 TokenRequest**（否则 projected token 无法签发），即配置

```
--service-account-issuer=<issuer，如 https://kubernetes.default.svc>
--service-account-signing-key-file=<sa 私钥>
--service-account-key-file=<对应公钥>        # 已有
--api-audiences=<issuer>                       # 不要把 internal-api 加进去
```

`internal-api` 不放进 `--api-audiences`，这样 audience 为 internal-api 的 token 不能被 kube-apiserver 接受，反之 kube-apiserver 的 token 也通不过本服务的 audience 检查。

```bash
make certs push-image          # 推送 uhub.service.ucloud.cn/andrew/sa-token-auth-demo:v0.1.0
export KUBECONFIG=...
make deploy                    # 应用 demo.yaml，创建 TLS Secret 和 CA ConfigMap
kubectl -n production logs -f worker-client
kubectl -n production logs -f controller-client
```

清单（`deploy/kubernetes/demo.yaml`）包含：Namespace `internal-api` 和 `production`；服务端 SA `internal-api`；客户端 SA `production/worker`、`production/controller`（`automountServiceAccountToken: false`，不挂载 kube-apiserver audience 的默认 token）；只允许 `create tokenreviews` 的 ClusterRole 及其 Binding（不使用 `system:auth-delegator`，更不用 cluster-admin）；服务端 Deployment + Service（挂载 TLS Secret，非 root，只读根文件系统）；两个客户端 Pod（projected token：audience `internal-api`，`expirationSeconds: 3600`，挂载 CA ConfigMap）。

### 在 UK8s 1.18.19 测试集群上的实测结果（2026-10-21）

UK8s 1.18 默认**没有**开启 TokenRequest：客户端 Pod 卡在 `failed to fetch token: the API server does not have TokenRequest endpoints enabled`，而带 `spec.audiences` 的 TokenReview 返回 500 `error validating audiences`（服务端按 fail closed 返回 503）。

在 3 台 master 的 `/etc/kubernetes/apiserver` 中逐台追加以下参数并重启（signing key 沿用 controller-manager 原本签 legacy token 的 `ca-key.pem`，与已有的 `--service-account-key-file=ca.pem` 是同一对密钥，存量 token 不受影响）：

```
--service-account-issuer=https://kubernetes.default.svc
--service-account-signing-key-file=/etc/kubernetes/ssl/ca-key.pem
--api-audiences=https://kubernetes.default.svc
```

之后端到端结果：

```
worker-client:
GET  /api/whoami -> 200 {"cluster":"<-cluster 参数>","namespace":"production","serviceAccount":"worker",...}
GET  /api/jobs   -> 200 []
POST /api/jobs   -> 403 forbidden
controller-client:
GET  /api/whoami -> 200 {...,"serviceAccount":"controller",...}
GET  /api/jobs   -> 200 []
POST /api/jobs   -> 201 {"id":1,"name":"demo","createdBy":"production/controller",...}
```

audience 隔离（worker 的三种 token 交叉测试）：

| token | kube-apiserver | internal-api |
| --- | --- | --- |
| projected，aud=`internal-api` | 401（拒绝） | 200 |
| projected，aud=`https://kubernetes.default.svc` | 403（认证通过，无 RBAC 权限） | 401 |
| legacy Secret token | 403（认证通过，无 RBAC 权限） | 401 |

服务端 RBAC 只有 `create tokenreviews`（`subjectaccessreviews` 和 `list secrets` 都是 no）；server 日志中没有出现任何 JWT。

**1.18 的坑**：kubelet 把 projected token 文件写成 `0600 root`，非 root 容器会报 `permission denied`；需要给 Pod 设 `securityContext.fsGroup`（清单里已加上），kubelet 才会把文件开放给该组读取。

## 测试与 Benchmark

```bash
go test ./...            # 或 make test（带 -race）
make bench
```

测试覆盖：有效 token、无 token、错误/畸形 token、伪造身份头、audience 不匹配、非 SA 身份、403 授权矩阵、缓存命中不重复 review、过期后重新 review（恰好到期也不使用）、撤销在 TTL 后生效、100 并发同 token 只 review 1 次、singleflight 结果过期不复用、超时和 API Server 不可用时 fail closed 且不缓存、日志不含 token、client 在 kubelet 式符号链接轮换后使用新 token、client 拒绝证书不受信任/非白名单 host/http、不同 token 不共享缓存、cache key 含 audience/cluster；`KubernetesTokenReviewer` 通过 client-go v0.18 访问一个模拟的 `authentication.k8s.io/v1` 端点，覆盖成功、audience、status.error、500、超时、server down 这些情况。

实测（Apple M4，go1.27.1，`go test -bench . -benchmem`；不同机器结果会不同）：

```
BenchmarkAuthCacheHit-10     8659335    148.9 ns/op    0 tokenreviews       0 B/op    0 allocs/op
BenchmarkAuthCacheMiss-10     487365   3231 ns/op      1.000 tokenreviews/op 1617 B/op 13 allocs/op
BenchmarkConcurrentAuth-10   9505088    142.4 ns/op    1.000 tokenreviews   0 B/op    0 allocs/op
```

CacheMiss 使用 fake reviewer，不包含真实网络往返；真实环境中 miss 的成本主要来自一次 API Server RTT。ConcurrentAuth 在整个 benchmark 中总共只调用了 1 次 TokenReview。

## 安全限制与攻击模型

防护：
- token 被窃取后发往其他内部服务：audience 绑定 + 本服务只接受 `internal-api`。
- kube-apiserver token 被拿来调用本服务：audience 不匹配，401。
- 伪造 Namespace/SA/Cluster 头：身份只来自 TokenReview，Cluster 只来自服务端配置。
- API Server 故障被利用来放行：fail closed，不缓存失败。
- 日志/响应泄露 token：不记录 Authorization，缓存只存哈希，whoami 不返回 token。
- 客户端把 token 发给错误的地方：只走 https、证书校验、host 白名单、不跟随跨 host 重定向。

不防护 / 需注意：
- 同一 audience 的 token 一旦泄露，在过期（≤ expirationSeconds）前可以被重放；本方案不做 sender-constrained（mTLS 绑定）。
- 所有使用 `internal-api` audience 的服务之间可以互相重放 token。需要隔离时，请给每个服务配置独立的 audience。
- 能读取 Pod 文件系统或 exec 进 Pod 的人可以拿到 token。
- 节点被攻破后，该节点上所有 Pod 的 token 都可被读取。
- 内存缓存按进程独立：多副本时每个副本各自 review。

## TokenReview 缓存的撤销延迟

Pod 或 SA 被删除、token 失效后，已经缓存的结果最多还能使用 **cache TTL（默认 30s）**，并且 TTL 从发起 review 之前开始计时，所以慢请求不会延长这个窗口。缓存不会延长 token 的真实有效期，但在 token 自然过期后的最多 30s 内，旧结果仍可能被接受。如果需要更快的撤销，可以调小 `-cache-ttl`，代价是更多 TokenReview。缓存条目上限为 10000，满了先清过期项再随机淘汰，淘汰只会导致多一次 review。

## Kubernetes 1.17 / 1.18 兼容性

- `authentication.k8s.io/v1` TokenReview（含 `spec.audiences` / `status.audiences`）从 1.13 起就有；1.17 和 1.18 均为 GA。
- `serviceAccountToken` projected volume（TokenRequest）在 1.17/1.18 是 beta，默认开启，但**需要 apiserver 配置 issuer 和 signing key**，否则就是上面实测到的报错。UK8s 1.18.19 默认没有配置。
- 未配置 `--api-audiences` 时，带 audiences 的 TokenReview 会返回 500（实测），本实现将其按 fail closed 处理。
- client-go v0.18 开始，typed client 要求传入 `ctx` 和 `CreateOptions`；与 1.17 apiserver 交互时使用的 API 相同。如果必须用 v0.17.x，只需把 `Create(ctx, tr, metav1.CreateOptions{})` 改成 `Create(tr)`，超时通过 `rest.Config.Timeout` 控制。
- kubelet 会在 token 到达 80% 生命周期或 24h 时刷新；`expirationSeconds` 最小为 600。
- 1.17/1.18 的 projected token 文件权限为 0600 root，以非 root 运行时必须设置 `fsGroup`（较新版本的 kubelet 会按 runAsUser 设置文件属主）。

## 与本地 JWT 验签方案的取舍

| | TokenReview + 短缓存（本方案） | 本地 JWKS 验签 |
| --- | --- | --- |
| 依赖 | 只需要 TokenReview RBAC | 需要分发公钥/JWKS（1.18 的 OIDC discovery 还是 alpha） |
| 撤销 | Pod/SA 删除后 ≤TTL 内生效 | 只能等 token 过期（除非额外查询 Pod/SA 是否存在） |
| API Server 压力 | 每个 token 每个 TTL 一次，并发合并 | 几乎为零 |
| 可用性 | API Server 不可用时，新 token 无法认证（fail closed） | 不依赖 API Server |
| 实现风险 | 低，由 apiserver 校验签名、过期、绑定对象 | 需要自己正确校验 alg/iss/aud/exp/nbf，并处理密钥轮换 |

对于已经有 HTTPS、规模中等、不希望引入额外 issuer 的内部 API，本方案更简单、更安全；当 QPS 或 token 数量大到 TokenReview 成为瓶颈，或者需要在 API Server 故障期间继续服务时，再考虑本地验签。
