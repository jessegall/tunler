# Pin the build stage to the build platform so Go cross-compiles natively
# (fast) instead of running under QEMU emulation for the target arch.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG LDFLAGS="-s -w -X github.com/jessegall/tunler/internal/server.Version=$VERSION -X main.version=$VERSION"
# Build the server for the target platform...
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags "$LDFLAGS" -o /out/tunler-server ./cmd/tunler-server
# ...and cross-compile every client binary, bundled into the image so
# /install works straight after `docker pull`.
RUN set -eu; \
    for p in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do \
      os=${p%-*}; arch=${p#*-}; ext=""; [ "$os" = windows ] && ext=".exe"; \
      GOOS=$os GOARCH=$arch CGO_ENABLED=0 \
        go build -ldflags "$LDFLAGS" -o /out/bin/tunler-$p$ext ./cmd/tunler; \
    done; \
    cd /out/bin; for f in tunler-*; do sha256sum "$f" > "$f.sha256"; done

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/tunler-server /usr/local/bin/tunler-server
# Client binaries live outside the data volume: Docker fills a named volume
# from the image only once, so binaries inside it would never be upgraded.
COPY --from=build /out/bin /usr/local/share/tunler/bin
VOLUME /var/lib/tunler
ENTRYPOINT ["tunler-server", "--data", "/var/lib/tunler", "--bin", "/usr/local/share/tunler/bin"]
