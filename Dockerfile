# Dockerfile
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /token-exchange-server

FROM gcr.io/distroless/static-debian12

# Copy the built static binary from the builder stage
COPY --from=builder /token-exchange-server /token-exchange-server

# Expose port (metadata)
EXPOSE 8080

# Command to run
ENTRYPOINT ["/token-exchange-server"]
