# Authentication Service (Auth v1)

A **production-style authentication & authorization backend** built with **Node.js, Express, MongoDB, and JWT**.
The focus is on **correctness, security, and interview-ready design**.

---

## ✨ Features

* User registration with hashed passwords
* Email verification (token-based, single-use, time-limited)
* Login with JWT **access tokens**
* Secure **refresh tokens** (httpOnly cookies, hashed in DB)
* Server-side logout
* Role-Based Access Control (RBAC): `user`, `admin`
* Forgot & reset password flow (secure, single-use tokens)

---

## 🧠 Design Highlights

* Short-lived **access tokens** + long-lived **refresh tokens**
* Refresh tokens stored hashed in DB → real logout & invalidation
* Email/password reset tokens are **never stored in plaintext**
* Login blocked until email is verified
* Clean separation of controllers and middleware

---

---

## 🔄 How It Works

1. **Register** → user created, email verification token generated
2. **Verify Email** → account activated
3. **Login** → access token returned, refresh token set as httpOnly cookie
4. **Access Protected Routes** → send access token in header
5. **Refresh Token** → new access token issued when expired
6. **Logout** → refresh token invalidated server-side

---

## ▶️ How to Use This Project

### 1️⃣ Setup

* Clone the repo
* Install dependencies
* Create a `.env` file with:

  * Database URL
  * JWT access & refresh secrets
* Start the server

### 2️⃣ Testing (Recommended: Postman)

* **Register**: `POST /auth/register`
* **Verify Email**: `POST /auth/verify-email`
* **Login**: `POST /auth/login`
* **Protected Route**:

  ```
  Authorization: Bearer <access_token>
  ```
* **Refresh Token**: handled via cookie
* **Logout**: `POST /auth/logout`
* **Forgot Password**: `POST /auth/forgot-password`
* **Reset Password**: `POST /auth/reset-password`

Access tokens are sent via headers; refresh tokens are stored securely as httpOnly cookies.

---

## 🔐 Security Notes

* Passwords hashed with bcrypt
* Refresh, reset, and verification tokens are hashed in DB
* Email enumeration prevented in password reset
* Refresh tokens invalidated on logout & password reset

---

## 🚧 Future Versions

* OAuth (Google/GitHub)
* Multi-device session management
* Redis / token families
* MFA / OTP

---

## 🏁 Summary

This project represents **Auth v1** — a complete, secure authentication system designed to be reused in real backend or full stack projects.
