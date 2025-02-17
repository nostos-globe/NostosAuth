# Usa la versión de Go compatible con tu proyecto
FROM golang:1.24 AS builder

# Define el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de Go Modules
COPY go.mod go.sum ./

# Descarga las dependencias
RUN go mod download

# Copia el resto del código fuente al contenedor
COPY . .

# Verifica que los archivos han sido copiados correctamente (debug)
RUN ls -lah /app

# Compila el servicio
RUN go build -o auth-service ./cmd/main.go


# Imagen final para producción (más ligera)
FROM gcr.io/distroless/base-debian12
=======
FROM golang:1.24 AS builder
>>>>>>> e7d130ddf8a0b1b03123163ee2e954505532178b

WORKDIR /app

# Copia el binario compilado desde el builder
COPY --from=builder /app/auth-service .

# Ejecuta el servicio
CMD ["/app/auth-service"]
