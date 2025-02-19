# Use a minimal Go image with Alpine for faster builds
FROM golang:1.24-alpine AS builder

# Install dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Verify that files are copied correctly (for debugging)
RUN ls -lah /app

# Set environment variables for cross-compilation
ENV CGO_ENABLED=0 GOOS=linux GOARCH=arm64

# Build the service
RUN go build -o auth-service ./cmd/main.go

# Use a lightweight final image
FROM alpine:latest

WORKDIR /app

# Copy only the compiled binary
COPY --from=builder /app/auth-service .

# Ensure the binary is executable
RUN chmod +x /app/auth-service

# Run the service
CMD ["/app/auth-service"]
