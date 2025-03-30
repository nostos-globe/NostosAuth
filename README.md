# Authentication Service

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

### 🔹 User Registration
```http
POST /register
```
Registers a new user.

### 🔹 Login
```http
POST /login
```
Authenticates a user and issues a JWT token.

### 🔹 Token Renewal
```http
POST /refresh-token
```
Generates a new access token using a refresh token.

### 🔹 Logout
```http
POST /logout
```
Invalidates the user's refresh token.

### 🔹 Authenticated User Information
```http
GET /profile
```
Retrieves information about the authenticated user.

### 🔹 Password Recovery
```http
POST /forgot-password
```
Sends a link to reset the password.

### 🔹 Password Reset
```http
POST /reset-password
```
Allows changing the password using a recovery token.

### 🔹 Password Change
```http
POST /update-password
```
Allows an authenticated user to change their password.

---

## ⚙️ Installation and Configuration

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

```bash
go mod tidy
```

### Execution

```bash
go run cmd/main.go
```
