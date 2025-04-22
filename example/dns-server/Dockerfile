FROM spx01/blocky:v0.25 AS blocky

FROM alpine:latest

RUN apk add --no-cache dnsmasq bind-tools tcpdump
COPY --from=blocky /app/blocky /bin/blocky

COPY entrypoint.sh .
COPY conf/ /etc/conf/
COPY certs/ /etc/certs/

EXPOSE 53/udp 8443/tcp

CMD ["./entrypoint.sh"]
