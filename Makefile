DIR := ${CURDIR}
build_dir := $(DIR)/.build
golangci_lint_version = v1.24.0
golangci_lint_dir = $(build_dir)/golangci_lint/$(golangci_lint_version)
golangci_lint_bin = $(golangci_lint_dir)/golangci-lint

$(golangci_lint_bin):
	@echo "Installing golangci-lint $(golangci_lint_version)..."
	@rm -rf $(dir $(golangci_lint_dir))
	@mkdir -p $(golangci_lint_dir)
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(golangci_lint_dir) $(golangci_lint_version)

lint: lint-code

lint-code: $(golangci_lint_bin)
	@cd ./v2; $(golangci_lint_bin) run ./...

test:
	@cd ./v2; go test ./...
