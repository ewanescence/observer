FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY . .

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /observer ./cmd/observer

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata su-exec && \
    adduser -D -u 10001 observer && \
    mkdir -p /data && \
    chown -R observer:observer /data

COPY --from=builder /observer /usr/local/bin/observer

WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/bin/sh", "-c", "mkdir -p \"$(dirname \"${OBSERVER_DB_PATH:-/data/observer.db}\")\" && chown -R observer:observer /data && exec su-exec observer /usr/local/bin/observer"]
