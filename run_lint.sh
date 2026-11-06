#!/bin/bash

set -exuo pipefail
lint_args=(--tests=false)
golangci-lint -c .golangci.yml run "${lint_args[@]}" ./...
