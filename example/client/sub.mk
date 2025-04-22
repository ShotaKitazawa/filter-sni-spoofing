.PHONY: build-client
build-client: client/ca.crt
	docker build -t local/client -f client/Dockerfile client/

client/ca.crt:
	cp ca.crt $@
