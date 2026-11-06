APP      := safeboard
BIN_DIR  := bin
CMD_DIR  := ./cmd/server

GO            ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: build run test test-race vet fmt fmt-check lint check clean

build:
	$(GO) build -o $(BIN_DIR)/$(APP) $(CMD_DIR)

run:
	$(GO) run $(CMD_DIR)

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "gofmt required for:"; \
		echo "$$files"; \
		exit 1; \
	fi

lint:
	$(GOLANGCI_LINT) -c .golangci.yml run ./...

check: fmt-check vet test-race lint

clean:
	rm -rf $(BIN_DIR)
