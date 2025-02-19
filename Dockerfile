# Use an official lightweight Go image
FROM golang:1.20 as builder

# Set necessary environment variables for ARM64
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=arm64

# Set working directory
WORKDIR /app

# Copy Go modules and install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the Go binary
RUN go build -o auth-service .

# Use a minimal base image
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/auth-service .
CMD ["./auth-service"]
