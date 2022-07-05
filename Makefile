.PHONY: rlnlib

SHELL := bash # the shell used internally by Make

GOBIN ?= $(shell which go)

rlnlib-cross:
	scripts/build-cross.sh
	cd lib/rln && cbindgen --config ../cbindgen.toml --crate rln --output ../../rln/librln.h --lang c

rlnlib:
	scripts/build.sh
	cd lib/rln && cbindgen --config ../cbindgen.toml --crate rln --output ../../rln/librln.h --lang c

test:
	LD_LIBRARY_PATH="${PWD}/libs/x86_64-unknown-linux-gnu/" go test ./... -count 1 -v