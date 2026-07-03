# tunler build & release
#
#   make build     build tunler + tunler-server for this machine into ./bin
#   make test      vet + race tests
#   make release   cross-compile all client + linux server binaries (with
#                  checksums) into ./dist

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION) -X github.com/jessegall/tunler/internal/server.Version=$(VERSION)
DIST    := dist

CLIENT_PLATFORMS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64
SERVER_PLATFORMS := linux-amd64 linux-arm64

.PHONY: build test release clean

build:
	mkdir -p bin
	go build -ldflags '$(LDFLAGS)' -o bin/ ./cmd/...

test:
	go vet ./...
	go test -race ./...

release: clean
	mkdir -p $(DIST)
	@for p in $(CLIENT_PLATFORMS); do \
		os=$${p%-*}; arch=$${p#*-}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		echo "building tunler-$$p$$ext"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' \
			-o $(DIST)/tunler-$$p$$ext ./cmd/tunler || exit 1; \
	done
	@for p in $(SERVER_PLATFORMS); do \
		os=$${p%-*}; arch=$${p#*-}; \
		echo "building tunler-server-$$p"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' \
			-o $(DIST)/tunler-server-$$p ./cmd/tunler-server || exit 1; \
	done
	@cd $(DIST) && for f in tunler-*; do \
		case $$f in *.sha256) continue;; esac; \
		(sha256sum $$f 2>/dev/null || shasum -a 256 $$f) > $$f.sha256; \
	done
	@ls -lh $(DIST)

clean:
	rm -rf bin $(DIST)
