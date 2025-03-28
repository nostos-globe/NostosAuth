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

### Register User
```http
POST /register
```
Registers a new user.

### Login
```http
POST /login
```
Authenticates a user and issues a JWT token.

### Logout
```http
POST /logout
```
Invalidates the user's refresh token and ends the session.

### Validate Token
```http
POST /validate
```
Validates the authenticity and validity of a JWT token.

### Forgot Password
```http
POST /forgot-password
```
Sends a password reset link to the user's email.

### Reset Password
```http
POST /reset-password
```
Allows the user to set a new password using a reset token.

### Update Password
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

### Prerequisites

- [Go](https://golang.org/) installed
- Configured database (MySQL, PostgreSQL, etc.)
- [HashiCorp Vault](https://www.vaultproject.io/) configured with necessary secrets

### Installation

Clone the repository and navigate into the project directory:
```sh
git clone <repository>
cd <directory>
```

Install dependencies:
```sh
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
```
