# Binaries are cross-compiled by `make image` (CGO disabled, static).
FROM scratch
COPY bin/linux-amd64/server /server
COPY bin/linux-amd64/client /client
USER 65532:65532
ENTRYPOINT ["/server"]
