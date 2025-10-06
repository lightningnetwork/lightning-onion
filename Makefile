PKG := github.com/lightningnetwork/lightning-onion
TOOLS_DIR := tools

GOBUILD := GO111MODULE=on go build -v
GOINSTALL := GO111MODULE=on go install -v

GOFILES = $(shell find . -type f -name '*.go')

RM := rm -f
CP := cp
MAKE := make
XARGS := xargs -L 1

# GO_VERSION is the Go version used for the release build, docker files, and
# GitHub Actions. This is the reference version for the project. All other Go
# versions are checked against this version.
GO_VERSION = 1.24.6

# Linting uses a lot of memory, so keep it under control by limiting the number
# of workers if requested.
ifneq ($(workers),)
LINT_WORKERS = --concurrency=$(workers)
endif

DOCKER_TOOLS = docker run \
  --rm \
  -v $(shell bash -c "mkdir -p /tmp/go-build-cache; echo /tmp/go-build-cache"):/root/.cache/go-build \
  -v $$(pwd):/build lightning-onion-tools

GREEN := "\\033[0;32m"
NC := "\\033[0m"
define print
	echo $(GREEN)$1$(NC)
endef

#? default: Run `make build`
default: build

#? all: Run `make build` and `make check`
all: build check

# ============
# INSTALLATION
# ============

#? build: Compile and build lightning-onion
build:
	@$(call print, "Compiling lightning-onion.")
	$(GOBUILD) $(PKG)/...

#? sphinx-cli: Build the sphinx-cli binary
sphinx-cli:
	@$(call print, "Building sphinx-cli.")
	$(GOBUILD) -o sphinx-cli ./cmd/main.go

# =======
# TESTING
# =======

#? check: Run `make unit`
check: unit

#? unit: Run unit tests
unit:
	@$(call print, "Running unit tests.")
	go test -v ./...

#? unit-cover: Run unit coverage tests
unit-cover:
	@$(call print, "Running unit coverage tests.")
	go test -coverprofile=coverage.txt -covermode=atomic ./...

#? unit-race: Run unit race tests
unit-race:
	@$(call print, "Running unit race tests.")
	env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" go test -race ./...

# =========
# UTILITIES
# =========

#? fmt: Fix imports and format source code
fmt: docker-tools
	@$(call print, "Fixing imports.")
	$(DOCKER_TOOLS) gosimports -w $(GOFILES)
	@$(call print, "Formatting source.")
	$(DOCKER_TOOLS) gofmt -l -w -s $(GOFILES)

#? check-go-version-yaml: Verify that the Go version is correct in all YAML files
check-go-version-yaml:
	@$(call print, "Checking for target Go version (v$(GO_VERSION)) in YAML files (*.yaml, *.yml)")
	./scripts/check-go-version-yaml.sh $(GO_VERSION)

#? check-go-version-dockerfile: Verify that the Go version is correct in all Dockerfile files
check-go-version-dockerfile:
	@$(call print, "Checking for target Go version (v$(GO_VERSION)) in Dockerfile files (*Dockerfile)")
	./scripts/check-go-version-dockerfile.sh $(GO_VERSION)

#? check-go-version: Verify that the Go version is correct in all project files
check-go-version: check-go-version-dockerfile check-go-version-yaml

#? fmt-check: Make sure source code is formatted and imports are correct
fmt-check: fmt
	@$(call print, "Checking fmt results.")
	if test -n "$$(git status --porcelain)"; then echo "code not formatted correctly, please run `make fmt` again!"; git status; git diff; exit 1; fi

#? lint-config-check: Verify golangci-lint configuration
lint-config-check: docker-tools
	@$(call print, "Verifying golangci-lint configuration.")
	$(DOCKER_TOOLS) golangci-lint config verify -v

#? lint: Lint source and check errors
lint: check-go-version lint-config-check
	@$(call print, "Linting source.")
	$(DOCKER_TOOLS) golangci-lint run -v $(LINT_WORKERS)

#? docker-tools: Build tools docker image
docker-tools:
	@$(call print, "Building tools docker image.")
	docker build -q -t lightning-onion-tools -f $(TOOLS_DIR)/Dockerfile .

#? clean: Clean source
clean:
	@$(call print, "Cleaning source.$(NC)")
	$(RM) coverage.txt

#? tidy-module: Run 'go mod tidy' for all modules
tidy-module:
	@$(call print, "Running 'go mod tidy' for main module")
	go mod tidy
	@$(call print, "Running 'go mod tidy' for tools module")
	cd $(TOOLS_DIR) && go mod tidy

#? tidy-module-check: Run 'go mod tidy' for all modules and check results
tidy-module-check: tidy-module
	if test -n "$$(git status --porcelain)"; then echo "modules not updated, please run `make tidy-module` again!"; git status; exit 1; fi

.PHONY: all \
	default \
	build \
	sphinx-cli \
	check \
	unit \
	unit-cover \
	unit-race \
	fmt \
	fmt-check \
	tidy-module \
	tidy-module-check \
	lint \
	lint-config-check \
	docker-tools \
	clean

#? help: Get more info on make commands
help: Makefile
	@echo " Choose a command run in lightning-onion:"
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'

.PHONY: help
