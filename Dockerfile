# Use an official lightweight Go image
FROM golang:1.24 as builder

# Set necessary environment variables for cross-compilation
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=arm64

# Set working directory
WORKDIR /app

# Copy go modules and install dependencies
COPY go.mod go.sum ./
RUN go mod tidy && go mod download

# Copy source code
COPY . .

# Ensure dependencies are installed
RUN go get -d ./...

# Build the Go binary with explicit architecture
RUN go build -o auth-service .

# Use a minimal base image
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/auth-service .
CMD ["./auth-service"]