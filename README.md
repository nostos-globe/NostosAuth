# Authentication Service

Este es un servicio de autenticación desarrollado en Go. Proporciona endpoints para el registro, inicio de sesión, manejo de tokens JWT y recuperación de contraseña.

## Características

- Registro de usuarios
- Autenticación mediante JWT
- Renovación de tokens
- Recuperación de contraseña
- Manejo de sesiones seguras

## Endpoints

### Registro de Usuario
```http
POST /register
```
Registra un nuevo usuario.

### Inicio de Sesión
```http
POST /login
```
Autentica un usuario y emite un token JWT.

### Renovación de Token
```http
POST /refresh-token
```
Genera un nuevo token de acceso usando un refresh token.

### Cierre de Sesión
```http
POST /logout
```
Invalida el refresh token del usuario.

### Información del Usuario Autenticado
```http
POST /profile
```
Obtiene la información del usuario autenticado.

### Recuperación de Contraseña
```http
POST /forgot-password
```
Envía un enlace para restablecer la contraseña.

### Restablecimiento de Contraseña
```http
POST /reset-password
```
Permite cambiar la contraseña con un token de recuperación.

### Cambio de Contraseña
```http
POST /update-password
```
Permite cambiar la contraseña de un usuario autenticado.

## Instalación y Configuración

### Prerrequisitos
- [Go](https://golang.org/) instalado
- Base de datos configurada (MySQL, PostgreSQL, etc.)

### Instalación
Clona el repositorio y navega al directorio del proyecto:
```sh
git clone <repositorio>
cd <directorio>
```

Instala las dependencias:
```sh
go mod tidy
```

### Configuración
Configura las variables de entorno en un archivo `.env`:
```
PORT=8080
DATABASE_URL=<URL_de_tu_DB>
JWT_SECRET=<secreto_para_tokens>
```

### Ejecución
```sh
go run main.go
```