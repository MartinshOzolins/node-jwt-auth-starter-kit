# Node JWT Auth Starter Kit

A starter kit for building **JWT-based authentication** in **Node.js + TypeScript** using **Express**, **Prisma**, and **PostgreSQL (or SQLite)**.  
Includes a full authentication flow with **sign-up, sign-in, email verification, password reset, refresh tokens, and logout**.

---

## 🚀 Features

- **JWT Authentication** (access + refresh tokens)
- **Secure cookie-based refresh tokens**
- **Email verification** with expiring tokens
- **Password reset flow** with confirm tokens
- **Prisma ORM** (SQLite/Postgres/MySQL support)
- **TypeScript** + ESLint + Prettier
- **Resend integration** for sending emails

---

## 📦 Getting Started

### 1. Clone & Install
```bash
git clone https://github.com/YOUR_USERNAME/node-jwt-auth-starter-kit.git
cd node-jwt-auth-starter-kit
npm install
```

### 2. Set up Prisma

Generate the client and push the schema to your database:

```bash
npx prisma generate
npx prisma db push
```

### 3. Run the server

#### Development 
```bash
npm run dev
```

#### Build & run
```bash
npm run build
npm start
```
