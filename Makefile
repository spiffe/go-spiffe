.PHONY: default all help

default: all

all: lint test

help:
	@echo "Usage: make <target>"
	@echo
	@echo "  all              - lints and tests the code"
	@echo "  lint             - lints the code"
	@echo "  test             - tests the code"
	@echo "  generate         - generate protocol buffer and gRPC stub code (default)"
	@echo "  generate-check   - ensure generated code is up to date"

# Used to force some rules to run every time
FORCE: ;

############################################################################
# OS/ARCH detection
############################################################################
os1=$(shell uname -s)
os2=
ifeq ($(os1),Darwin)
os1=darwin
os2=osx
else ifeq ($(os1),Linux)
os1=linux
os2=linux
else ifeq (,$(findstring MYSYS_NT-10-0-, $(os1)))
os1=windows
os2=windows
else
$(error unsupported OS: $(os1))
endif

arch1=$(shell uname -m)
ifeq ($(arch1),x86_64)
arch2=amd64
else ifeq ($(arch1),aarch64)
arch2=arm64
else ifeq ($(arch1),arm64)
arch2=arm64
else
$(error unsupported ARCH: $(arch1))
endif

#############################################################################
# Vars
#############################################################################

build_dir := ${CURDIR}/.build/$(os1)-$(arch1)

protoc_version = 30.2
ifeq ($(os1),windows)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-win64.zip
else ifeq ($(arch1),arm64)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-aarch_64.zip
else ifeq ($(arch1),aarch64)
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-aarch_64.zip
else
protoc_url = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(os2)-$(arch1).zip
endif
protoc_dir = $(build_dir)/protoc/$(protoc_version)
protoc_bin = $(protoc_dir)/bin/protoc

protoc_gen_go_version := $(shell grep google.golang.org/protobuf go.mod | awk '{print $$2}')
protoc_gen_go_base_dir := $(build_dir)/protoc-gen-go
protoc_gen_go_dir := $(protoc_gen_go_base_dir)/$(protoc_gen_go_version)-go$(go_version)
protoc_gen_go_bin := $(protoc_gen_go_dir)/protoc-gen-go

protoc_gen_go_grpc_version := v1.5.1
protoc_gen_go_grpc_base_dir := $(build_dir)/protoc-gen-go-grpc
protoc_gen_go_grpc_dir := $(protoc_gen_go_grpc_base_dir)/$(protoc_gen_go_grpc_version)-go$(go_version)
protoc_gen_go_grpc_bin := $(protoc_gen_go_grpc_dir)/protoc-gen-go-grpc

golangci_lint_version = v2.0.2
golangci_lint_dir = $(build_dir)/golangci_lint/$(golangci_lint_version)
golangci_lint_bin = $(golangci_lint_dir)/golangci-lint

apiprotos := \
	proto/spiffe/workload/workload.proto \

#############################################################################
# Toolchain
#############################################################################

go_version_full := 1.24.6
go_version := $(go_version_full:.0=)
go_dir := $(build_dir)/go/$(go_version)

ifeq ($(os1),windows)
	go_bin_dir = $(go_dir)/go/bin
	go_url = https://storage.googleapis.com/golang/go$(go_version).$(os1)-$(arch2).zip
	exe=".exe"
else
	go_bin_dir = $(go_dir)/bin
	go_url = https://storage.googleapis.com/golang/go$(go_version).$(os1)-$(arch2).tar.gz
	exe=
endif

go_path := PATH="$(go_bin_dir):$(PATH)"

go-check:
ifeq (go$(go_version), $(shell $(go_path) go version 2>/dev/null | cut -f3 -d' '))
else ifeq ($(os1),windows)
	@echo "Installing go$(go_version)..."
	rm -rf $(dir $(go_dir))
	mkdir -p $(go_dir)
	curl -o $(go_dir)\go.zip -sSfL $(go_url)
	unzip -qq $(go_dir)\go.zip -d $(go_dir)
else
	@echo "Installing go$(go_version)..."
	$(E)rm -rf $(dir $(go_dir))
	$(E)mkdir -p $(go_dir)
	$(E)curl -sSfL $(go_url) | tar xz -C $(go_dir) --strip-components=1
endif


#############################################################################
# Linting
#############################################################################

.PHONY: lint
lint: $(golangci_lint_bin) | go-check
	@PATH="$(go_bin_dir):$(PATH)" $(golangci_lint_bin) run ./...

$(golangci_lint_bin):
	@echo "Installing golangci-lint $(golangci_lint_version)..."
	@rm -rf $(dir $(golangci_lint_dir))
	@mkdir -p $(golangci_lint_dir)
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(golangci_lint_dir) $(golangci_lint_version)

#############################################################################
# Tidy
#############################################################################

.PHONY: test
tidy: | go-check
	@$(go_path) go mod tidy

#############################################################################
# Testing
#############################################################################

.PHONY: test
test: | go-check
	@$(go_path) go test -race ./...

#############################################################################
# Code Generation
#############################################################################

.PHONY: generate
generate: $(apiprotos:.proto=.pb.go) $(apiprotos:.proto=_grpc.pb.go)

%_grpc.pb.go: %.proto $(protoc_bin) $(protoc_gen_go_grpc_bin) FORCE
	@echo "compiling proto $<..."
	@cd "$(dir $<)" && PATH="$(protoc_gen_go_grpc_dir):$(PATH)" \
		$(protoc_bin) \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(notdir $<)

%.pb.go: %.proto $(protoc_bin) $(protoc_gen_go_bin) FORCE
	@echo "compiling gRPC $<..."
	@cd "$(dir $<)" && PATH="$(protoc_gen_go_dir):$(PATH)" \
		$(protoc_bin) \
		--go_out=. --go_opt=paths=source_relative \
		$(notdir $<)

$(protoc_bin):
	@echo "Installing protoc $(protoc_version)..."
	@rm -rf $(dir $(protoc_dir))
	@mkdir -p $(protoc_dir)
	@curl -sSfL $(protoc_url) -o $(build_dir)/tmp.zip; unzip -q -d $(protoc_dir) $(build_dir)/tmp.zip; rm $(build_dir)/tmp.zip

$(protoc_gen_go_bin): | go-check
	@echo "Installing protoc-gen-go $(protoc_gen_go_version)..."
	@rm -rf $(protoc_gen_go_base_dir)
	@mkdir -p $(protoc_gen_go_dir)
	@GOBIN="$(protoc_gen_go_dir)" $(go_path) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(protoc_gen_go_version)

$(protoc_gen_go_grpc_bin): | go-check
	@echo "Installing protoc-gen-go-grpc $(protoc_gen_go_grpc_version)..."
	@rm -rf $(protoc_gen_go_grpc_base_dir)
	@mkdir -p $(protoc_gen_go_grpc_dir)
	@GOBIN=$(protoc_gen_go_grpc_dir) $(go_path) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(protoc_gen_go_grpc_version)

#############################################################################
# Code Generation Checks
#############################################################################

git_dirty := $(shell git status -s)

.PHONY: generate-check
generate-check:
ifneq ($(git_dirty),)
	$(error generate-check must be invoked on a clean repository)
endif
	@$(MAKE) generate
	@$(MAKE) git-clean-check

.PHONY: git-clean-check
git-clean-check:
ifneq ($(git_dirty),)
	git diff
	@echo "Git repository is dirty!"
	@false
else
	@echo "Git repository is clean."
endif
