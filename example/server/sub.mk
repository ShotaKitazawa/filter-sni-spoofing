.PHONY: build-server
build-server: server/certs/server.crt
	docker build -t local/server -f server/Dockerfile server/

server/certs/server.key:
	openssl genrsa -out $@ 2048

server/certs/server.csr: server/certs/server.key server/certs/csr.conf
	openssl req -new -key server/certs/server.key -out $@ -config server/certs/csr.conf

server/certs/server.crt: server/certs/csr.conf server/certs/server.csr 
	openssl x509 -req -in server/certs/server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $@ -days 10000 -extensions v3_ext -extfile server/certs/csr.conf -sha256


