FROM alpine:3.7

RUN apk add --no-cache pdns pdns-backend-pipe python3

EXPOSE 53/tcp 53/udp

COPY nipio/backend.py /opt/nip.io/
COPY nipio/backend.conf /opt/nip.io/
COPY pdns/pdns.conf /etc/pdns/pdns.conf

CMD ["/usr/sbin/pdns_server", "--daemon=no", "--disable-syslog", "--write-pid=no"]
