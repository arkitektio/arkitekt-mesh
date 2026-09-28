# The lab's tsnet peer, built against TS_VERSION of tailscale (the same code
# tailscaled runs), so the tests can run against several client versions.
FROM golang:1.26-bookworm AS build
ARG TS_VERSION=v1.102.5
WORKDIR /src
COPY main.go .
RUN go mod init lab-peer && go get tailscale.com@${TS_VERSION} && go mod tidy \
    && CGO_ENABLED=0 go build -trimpath -o /lab-peer .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /lab-peer /usr/local/bin/lab-peer
ENTRYPOINT ["/usr/local/bin/lab-peer"]
