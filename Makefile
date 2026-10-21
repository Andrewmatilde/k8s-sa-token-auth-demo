REGISTRY ?= uhub.service.ucloud.cn/andrew
IMAGE    ?= $(REGISTRY)/sa-token-auth-demo
TAG      ?= v0.1.0
PLATFORM ?= linux/amd64

.PHONY: help build test bench certs run-dev image push-image deploy
help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build local binaries into bin/
	go build -o bin/server ./cmd/server
	go build -o bin/client ./cmd/client

test: ## Run unit tests with the race detector
	go test -race -count=1 ./...

bench: ## Run benchmarks
	go test -run '^$$' -bench . -benchmem ./internal/auth/

certs: ## Generate demo CA + server certificate into certs/
	hack/gen-certs.sh certs

run-dev: build certs ## Run server with the DEVELOPMENT-ONLY fake reviewer
	bin/server -dev-fake-reviewer -cluster local-dev -tls-cert certs/tls.crt -tls-key certs/tls.key

image: ## Cross-compile linux/amd64 binaries for the image
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/linux-amd64/server ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/linux-amd64/client ./cmd/client

push-image: image ## Build and push $(IMAGE):$(TAG)
	docker buildx build --platform $(PLATFORM) -t $(IMAGE):$(TAG) --push .

deploy: ## Create TLS secret/CA configmap and apply manifests (needs certs/)
	kubectl apply -f deploy/kubernetes/demo.yaml
	kubectl -n internal-api create secret tls internal-api-tls --cert=certs/tls.crt --key=certs/tls.key --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n production create configmap internal-api-ca --from-file=ca.crt=certs/ca.crt --dry-run=client -o yaml | kubectl apply -f -
