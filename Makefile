.PHONY: build test serve clean

# Build WASM package for browser
build:
	wasm-pack build --target web --release

# Run all Rust tests (native)
test:
	cargo test --release

# Install webapp dependencies and start dev server
serve: build
	cd webapp && npm install && npx vite --host 0.0.0.0

# Remove build artifacts
clean:
	cargo clean
	rm -rf pkg/
	rm -rf webapp/node_modules webapp/dist
	rm -rf target/
