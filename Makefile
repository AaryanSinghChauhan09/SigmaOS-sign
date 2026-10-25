.PHONY: all build test clean install

all: build

build:
	cargo build --release

test:
	cargo test

clean:
	cargo clean

install: build
	install -Dm755 target/release/sigmasign /usr/local/bin/sigmasign
