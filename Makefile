.PHONY: build test serve clean ensure-wasm-pack

CARGO ?= cargo
CARGO_HOME ?= $(HOME)/.cargo
WASM_PACK := $(CARGO_HOME)/bin/wasm-pack
WASM_PACK_INSTALL := $(CARGO) install --locked wasm-pack

# Build WASM package for browser.
# This target only assumes Rust/Cargo are installed. If wasm-pack is missing,
# it is installed automatically into $(CARGO_HOME)/bin and reused afterwards.
build: ensure-wasm-pack
	$(WASM_PACK) build --target web --release

ensure-wasm-pack:
	@if [ ! -x "$(WASM_PACK)" ]; then \
		echo "Installing wasm-pack via cargo..."; \
		$(WASM_PACK_INSTALL); \
	fi

# Run all Rust tests (native)
test:
	$(CARGO) test --release

# Install webapp dependencies and start dev server
serve: build
	cd webapp && npm install && npx vite --host 0.0.0.0

# Remove build artifacts
clean:
	$(CARGO) clean
	rm -rf pkg/
	rm -rf webapp/node_modules webapp/dist
	rm -rf target/
