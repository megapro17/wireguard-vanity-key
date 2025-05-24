FROM golang:latest AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -v -trimpath -ldflags '-d -w -s'

FROM scratch
ARG REVISION
LABEL org.opencontainers.image.title="Fast WireGuard vanity key generator"
LABEL org.opencontainers.image.description="This tool searches for a WireGuard Curve25519 keypair with a base64-encoded public key that has a specified prefix"
LABEL org.opencontainers.image.authors="Alexander Yastrebov <yastrebov.alex@gmail.com>"
LABEL org.opencontainers.image.url="https://github.com/AlexanderYastrebov/wireguard-vanity-key"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"
LABEL org.opencontainers.image.revision="${REVISION}"

COPY --from=builder /app/wireguard-vanity-key /wireguard-vanity-key

ENTRYPOINT ["/wireguard-vanity-key"]
