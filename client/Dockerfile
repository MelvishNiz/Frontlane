FROM alpine:3.21

RUN apk add --no-cache iproute2 wireguard-tools

COPY --chmod=0755 entrypoint.sh /usr/local/bin/frontlane-client

ENTRYPOINT ["/usr/local/bin/frontlane-client"]
