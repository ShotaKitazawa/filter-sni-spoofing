.PHONY: build-dns-server
build-dns-server: dns-server/certs/server.crt
	docker build -t local/dns-server -f dns-server/Dockerfile dns-server/

dns-server/certs/server.key:
	openssl genrsa -out $@ 2048

dns-server/certs/server.csr: dns-server/certs/server.key dns-server/certs/csr.conf
	openssl req -new -key dns-server/certs/server.key -out $@ -config dns-server/certs/csr.conf

dns-server/certs/server.crt: dns-server/certs/csr.conf dns-server/certs/server.csr 
	openssl x509 -req -in dns-server/certs/server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $@ -days 10000 -extensions v3_ext -extfile dns-server/certs/csr.conf -sha256


