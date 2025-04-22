FROM envoyproxy/envoy:contrib-debug-dev
RUN apt update -y && apt install -y iproute2 iputils-ping curl iptables tcpdump bind9-dnsutils
COPY ./envoy.yaml /etc/envoy/envoy.yaml
COPY ./filter_sni_spoofing.wasm /etc/envoy/wasm/filter_sni_spoofing.wasm
COPY ./ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates

ENTRYPOINT ["envoy", "-c", "/etc/envoy/envoy.yaml", "-l", "debug"]
