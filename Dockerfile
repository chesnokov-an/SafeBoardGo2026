# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/safeboard \
    ./cmd/server

FROM alpine:3.20

RUN adduser -D -H -u 10001 app

WORKDIR /app

COPY --from=builder /out/safeboard ./safeboard
COPY cmd/server/config.yaml ./config.yaml

ENV API_ADDRESS=0.0.0.0:8080 \
    LOG_LEVEL=INFO

USER app

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health >/dev/null || exit 1

ENTRYPOINT ["./safeboard", "-config", "config.yaml"]
