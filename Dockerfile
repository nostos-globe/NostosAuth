# Usa una imagen de Go basada en Alpine para compilar el servicio
FROM golang:1.24-alpine AS builder

# Instala dependencias necesarias para la compilación
RUN apk add --no-cache git

# Define el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de Go Modules y descarga dependencias
COPY go.mod go.sum ./
RUN go mod download

# Copia el resto del código fuente al contenedor
COPY . .

# Configura GOARCH para compilar en la arquitectura correcta
ARG TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
        "linux/arm64") GOARCH=arm64 ;; \
        "linux/amd64") GOARCH=amd64 ;; \
        *) GOARCH=amd64 ;; \
    esac && \
    CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o auth-service ./cmd/main.go

# Imagen final para producción basada en Alpine (más ligera)
FROM alpine:latest

# Crea el directorio de trabajo
WORKDIR /app

# Copia el binario compilado desde el builder
COPY --from=builder /app/auth-service .

# Define el usuario no root por seguridad
RUN adduser -D -g '' appuser && chown -R appuser /app
USER appuser

# Ejecuta el servicio
CMD ["/app/auth-service"]
