.PHONY: all deps build sysimage test clean

all: deps sysimage

deps:
	cd deps/bandersnatch-ffi && cargo build --release
	julia --project=. -e 'using Pkg; Pkg.instantiate()'

sysimage: deps
	julia --project=. build/build_app.jl

test: deps
	julia --project=. -e 'using Pkg; Pkg.test()'

run: sysimage
	julia -J build/romio.so --project=. bin/romio $(ARGS)

clean:
	rm -rf build/romio build/romio.so
	cd deps/bandersnatch-ffi && cargo clean
