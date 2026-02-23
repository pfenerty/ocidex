# Build stage
FROM docker.io/golang:1.25-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/ocidex ./cmd/ocidex

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/bin/ocidex /usr/local/bin/ocidex

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/ocidex"]
