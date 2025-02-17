FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o auth-service

# Crear una imagen ligera para producción
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/auth-service .

# Copiar archivos de configuración si son necesarios
COPY .env .

# Exponer el puerto del servicio
EXPOSE 8080

# Comando para ejecutar el servicio
CMD ["./auth-service"]
