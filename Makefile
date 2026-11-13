# RyAgent build/deploy helpers.
#
# Compile locally, package in Docker on the server:
#   - the server has no Go/npm toolchain and only ~3.6GB RAM, so compiling the
#     120k-line Go tree or the Next frontend there is slow and can OOM;
#   - the runtime image reuses the already-downloaded ARTEX tool layer, so the
#     server-side build only copies the static binary (one small layer).
#
# One image tag only: artex:ry. No v1/v2/date suffixes.
SHELL := /bin/bash

IMAGE       ?= artex:ry
CONTAINER   ?= artex-artex-1
HOST        ?= 127.0.0.1
PORT        ?= 22233
REMOTE      ?= ubuntu@$(HOST)
REMOTE_DIR  ?= ry-build
ARTEX_DIR   ?= ~/ARTEX
SSH_OPTS    ?= -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
PASS        := $(shell grep -m1 '^password' tmp/creds.txt 2>/dev/null | cut -d= -f2-)
# `env -i`: GNU make exports MAKEFLAGS/MAKE_HOST/etc, and that environment makes
# OpenSSH reject the hostname on this macOS box. Clear it for the SSH children;
# PATH is preserved so sshpass/ssh still resolve, and the rest of the recipe
# stays a normal shell.
SSH         := env -i PATH="$$PATH" HOME="$$HOME" sshpass -p '$(PASS)' ssh $(SSH_OPTS) -p $(PORT) $(REMOTE)
RSYNC       := rsync -az -e "env -i PATH=$$PATH HOME=$$HOME sshpass -p '$(PASS)' ssh $(SSH_OPTS) -p $(PORT)"

.PHONY: help frontend dist sync image deploy logs clean test fmt check

help:
	@echo "make frontend  build Next static export into server/webui/dist"
	@echo "make dist      cross-compile linux/amd64 binary with embedded UI"
	@echo "make sync      upload binary + deploy files to $(REMOTE):$(REMOTE_DIR)"
	@echo "make image     docker build $(IMAGE) on the server"
	@echo "make deploy    image + recreate the artex container (keeps Postgres/data)"
	@echo "make logs      tail the running container"
	@echo "make test      fast local tests (full ./... needs Postgres)"
	@echo "make clean     prune dangling images/build cache on the server"

frontend:
	cd web && npm ci --no-audit --no-fund --registry=https://registry.npmmirror.com
	cd web && npm run build:static
	rsync -a --delete web/out/ server/webui/dist/

dist:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags embedui -trimpath \
	  -ldflags="-s -w -X main.version=ryagent-dev" -o dist/amd64/artex ./cmd/artex

sync:
	$(RSYNC) dist/amd64/artex $(REMOTE):$(REMOTE_DIR)/artex
	$(RSYNC) deploy/Dockerfile.ry $(REMOTE):$(REMOTE_DIR)/Dockerfile
	$(RSYNC) deploy/docker-compose.ry.yml $(REMOTE):$(REMOTE_DIR)/docker-compose.ry.yml

image:
	$(SSH) 'cd $(REMOTE_DIR) && DOCKER_BUILDKIT=1 docker build -t $(IMAGE) .'

deploy: image
	$(SSH) 'mkdir -p $(ARTEX_DIR)/keys && cp $(REMOTE_DIR)/docker-compose.ry.yml $(ARTEX_DIR)/docker-compose.ry.yml && \
	  cd $(ARTEX_DIR) && docker compose -f docker-compose.yml -f docker-compose.ry.yml up -d artex && \
	  sleep 3 && docker ps --filter name=$(CONTAINER) --format "{{.Names}} {{.Status}}"'

logs:
	$(SSH) 'docker logs --tail 80 $(CONTAINER)'

clean:
	$(SSH) 'docker builder prune -f; docker image prune -f; df -h / | tail -1'

test:
	go test ./intercept ./agent ./db
	go test ./server -run 'TestCheckProxyHTTP|TestNormalizeProxyLine|TestParseProxyCandidates|TestParseProxyJSONShapes|TestExtractEgressIP|TestHostIsPrivateLiterals|TestDecodeJSONObject|TestToolProxyHarvestSchema|TestProxySourceDTOHidesCredentials|TestFofaCandidates|TestHunterCandidates'

fmt:
	gofmt -l -w agent cmd db intercept server

check:
	gofmt -l agent cmd db intercept server
	go vet ./agent ./db ./intercept ./server ./cmd/artex
