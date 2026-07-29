# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP build harness. `make` is not installed on the primary Windows dev box, so the
# executable recipe lives in scripts/verify.sh (POSIX) and scripts/verify.ps1 (Windows);
# these targets are thin dispatchers for CI and Unix dev boxes that do have make. The
# behaviour is identical to the scripts. Go targets force GOWORK=off (see scripts).
#
# Usage:
#   make              # full verification recipe (oracles -> Go -> Rust -> vector drift)
#   make oracle       # regenerate every conformance vector from its independent oracle
#   make go-test      # Go build + vet + test -race
#   make rust-test    # Rust build + test

.PHONY: all verify oracle go-test rust-test

all: verify

verify:
	bash scripts/verify.sh

oracle:
	@for f in tools/*_oracle.py; do echo "oracle: $$f"; python "$$f"; done

go-test:
	cd impl/go && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off CGO_ENABLED=1 go test -race -count=1 ./...

rust-test:
	cd impl/rust && cargo build && cargo test
