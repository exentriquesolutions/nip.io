FROM alpine:3.7

RUN apk add --no-cache pdns pdns-backend-pipe python2

EXPOSE 53/tcp 53/udp

COPY nipio/backend.py /usr/local/bin
RUN chmod +x /usr/local/bin/backend.py
COPY nipio/backend.conf /usr/local/bin
COPY pdns/pdns.conf /etc/pdns/pdns.conf

CMD ["/usr/sbin/pdns_server", "--daemon=no", "--disable-syslog", "--write-pid=no"]