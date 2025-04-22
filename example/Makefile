.PHONY: build-images
build-images: ca.key ca.crt build-client build-dns-server build-envoy build-server clean

ca.key:
	openssl genrsa -out ca.key 2048

ca.crt: ca.key
	openssl req -x509 -new -nodes -key ca.key -subj "/C=JP" -days 10000 -out ca.crt

.PHONY: clean
clean:
	rm -rf ca.srl


include */sub.mk
