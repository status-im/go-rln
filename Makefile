.PHONY: rlnlib

rlnlib:
	scripts/build.sh
	cd lib/rln && cbindgen --config ../cbindgen.toml --crate rln --output ../../rln/librln.h --lang c
