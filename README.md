# Authentication Service

This is an authentication service developed in Go. It provides endpoints for user registration, login, JWT token handling, password recovery, and secure session management.

## Features

- User registration
- JWT-based authentication
- Token refresh mechanism
- Password recovery
- Secure session handling
- Environment configuration via [HashiCorp Vault](https://www.vaultproject.io/)

## Endpoints
This is an authentication service developed in Go. It provides endpoints for registration, login, JWT token management, and password recovery.

---

## 🚀 Features

- User registration  
- JWT authentication  
- Token renewal  
- Password recovery  
- Secure session management  

---

## 📌 Endpoints

### Register User
### 🔹 User Registration
```http
POST /register
```
Registers a new user.
Registers a new user.

### Login
### 🔹 Login
```http
POST /login
```
Authenticates a user and issues a JWT token.
Authenticates a user and issues a JWT token.

### 🔹 Token Renewal
```http
POST /refresh-token
```
Generates a new access token using a refresh token.

### Logout
### 🔹 Logout
```http
POST /logout
```
Invalidates the user's refresh token and ends the session.
Invalidates the user's refresh token.

### Validate Token
### 🔹 Authenticated User Information
```http
POST /validate
GET /profile
```
Validates the authenticity and validity of a JWT token.
Retrieves information about the authenticated user.

### Forgot Password
### 🔹 Password Recovery
```http
POST /forgot-password
```
Sends a password reset link to the user's email.
Sends a link to reset the password.

### Reset Password
### 🔹 Password Reset
```http
POST /reset-password
```
Allows the user to set a new password using a reset token.
Allows changing the password using a recovery token.

### Update Password
### 🔹 Password Change
```http
POST /update-password
```
Allows an authenticated user to change their current password.

### Get Profile
```http
GET /profile
```
Retrieves information about the currently authenticated user.

### Refresh Token
```http
POST /refresh-token
```
Generates a new access token using a refresh token.

## Installation and Setup
Allows an authenticated user to change their password.

---

## ⚙️ Installation and Configuration

### Prerequisites

- [Go](https://golang.org/) installed
- Configured database (MySQL, PostgreSQL, etc.)
- [HashiCorp Vault](https://www.vaultproject.io/) configured with necessary secrets

### Installation

Clone the repository and navigate into the project directory:
```sh
git clone <repository>
cd <directory>
### Prerequisites

- Go installed  
- Configured database (MySQL, PostgreSQL, etc.)

### Installation

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/nostos-globe/NostosAuth
cd NostosAuth
```

Install dependencies:
```sh
Install dependencies:

```bash
go mod tidy
```

### Configuration

This service retrieves configuration secrets (e.g., database URL, JWT secret) from Vault. Ensure the following secrets are available in your Vault instance:

- `DATABASE_URL`
- `JWT_SECRET`
- Any other required variables (e.g., SMTP credentials if sending emails)

The application must be authorized to access Vault, either via token, AppRole, or Kubernetes Auth (depending on your setup).

### Running the Application
```sh
go run main.go
### Execution

```bash
go run cmd/main.go
```

