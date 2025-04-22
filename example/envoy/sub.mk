.PHONY: build-envoy
build-envoy: envoy/filter_sni_spoofing.wasm envoy/ca.crt
	docker build -t local/envoy -f envoy/Dockerfile envoy/

envoy/filter_sni_spoofing.wasm: ../target/wasm32-wasip1/release/filter_sni_spoofing.wasm
	cp $< $@

.PHONY: ../target/wasm32-wasip1/release/filter_sni_spoofing.wasm
../target/wasm32-wasip1/release/filter_sni_spoofing.wasm:
	cd ../; rustup target add wasm32-wasip1; cargo build --target wasm32-wasip1 --release

envoy/ca.crt:
	cp ca.crt $@
