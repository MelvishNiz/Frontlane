FROM golang:1.24-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/frontlane ./cmd/frontlane

FROM alpine:3.21
RUN apk add --no-cache ca-certificates iproute2 libqrencode-tools wireguard-tools
RUN addgroup -S frontlane && adduser -S -G frontlane frontlane
COPY --from=build /out/frontlane /usr/local/bin/frontlane
EXPOSE 8080/tcp 51820/udp
ENTRYPOINT ["frontlane"]
