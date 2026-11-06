#!/usr/bin/env bash

set -euo pipefail

golangci-lint -c .golangci.yml run ./...
