# Build stage
FROM docker.io/golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/ocidex ./cmd/ocidex

# Runtime stage
FROM docker.io/alpine:latest

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 ocidex

COPY --from=builder /app/bin/ocidex /usr/local/bin/ocidex

USER ocidex
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["ocidex"]
