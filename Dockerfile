# Usa la versión de Go compatible con tu proyecto
FROM golang:1.24 AS builder

# Set the target platform for ARM (Raspberry Pi)
ENV GOOS=linux
ENV GOARCH=arm
ENV GOARM=7

# Set working directory
WORKDIR /app

# Copy Go modules files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Verify files (debug)
RUN ls -lah /app

# Build the service for ARM
RUN CGO_ENABLED=0 go build -o auth-service ./cmd/main.go

# Final stage
FROM arm32v7/debian:bullseye-slim

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/auth-service .

# Run the service
CMD ["/app/auth-service"]
