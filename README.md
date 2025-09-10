# dotnet-auth-api

A minimal, production-minded **JWT authentication API** built with **.NET 9 Minimal API + EF Core 9 + MySQL + BCrypt + Swagger**.

Designed for a Unity client (separate repo), but generic enough for any client.

---

## ✨ Features

- Sign up & sign in: `POST /auth/signup`, `POST /auth/login`
- Username & email availability: `GET /auth/check-username`, `GET /auth/check-email`
- JWT issuance on login and a protected endpoint: `GET /users/me`
- Passwords stored as **BCrypt salted hashes** (never plaintext)
- Swagger UI for quick testing
- CORS enabled (open in dev; restrict in prod)
- Clean structure with **feature-based endpoint modules**

---

## 🚀 Quick Start

### Prerequisites
- .NET 9 SDK
- MySQL 8.0+  

### Configure (Development)
Update `appsettings.Development.json` with your local values:
```json
{
  "ConnectionStrings": {
    "Default": "Server=localhost;Port=3306;Database=unity_auth_db;User=root;Password=CHANGEME;SslMode=None;"
  },
  "Jwt": {
    "Issuer": "DotnetAuthSample",
    "Audience": "DotnetAuthSample",
    "Key": "change-this-dev-key",
    "ExpiresMinutes": 60
  }
}
```

> **Production:** never hardcode secrets. Provide them via **environment variables** (see [Configuration](https://learn.microsoft.com/en-us/dotnet/core/extensions/configuration)).

### Database (EF Core)
```bash
dotnet tool install --global dotnet-ef
dotnet add package Microsoft.EntityFrameworkCore.Design --version 9.*
dotnet ef migrations add InitialCreate
dotnet ef database update
```

### Run
```bash
dotnet run
```
Open **http://localhost:5042/swagger** to test endpoints.  

## 🧭 Endpoints (Overview)

- `GET /auth/check-username?username=edin` → `{ "exists": true|false, "message": "..." }`
- `GET /auth/check-email?email=a@b.com` → `{ "exists": true|false, "message": "..." }`
- `POST /auth/signup` → `201 Created` | `409 Conflict`
- `POST /auth/login` → `200 OK { token, username, email }` | `401 Unauthorized`
- `GET /users/me` *(JWT required)* → `200 { username, email }` | `401 Unauthorized`

> For protected requests, send the header: `Authorization: Bearer <JWT>`

---

## 🔐 Security

- Passwords are **BCrypt** hashes (never store/log plaintext)
- Use **HTTPS** in production
- Add **rate limiting / lockout** for repeated failed logins
- Rotating the JWT signing key invalidates existing tokens (plan key rotation if needed)

## 📜 License

MIT
