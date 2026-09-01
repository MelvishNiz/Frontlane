FROM golang:1.24-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/privatewg ./cmd/privatewg

FROM alpine:3.21
RUN apk add --no-cache ca-certificates iproute2 libqrencode-tools wireguard-tools
RUN addgroup -S privatewg && adduser -S -G privatewg privatewg
COPY --from=build /out/privatewg /usr/local/bin/privatewg
EXPOSE 8080/tcp 51820/udp
ENTRYPOINT ["privatewg"]
