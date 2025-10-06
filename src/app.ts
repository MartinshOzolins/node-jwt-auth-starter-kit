import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import cookieParser from "cookie-parser";
import morgan from "morgan";

import authRouter from "./routes/auth.routes.js";
import userRouter from "./routes/user.routes.js";
import { errorHandler } from "./services/error.service.js";
import "dotenv/config";

//
const NODE_ENV = process.env.NODE_ENV ?? "development";
const CORS_ORIGINS = (process.env.CORS_ORIGINS ?? "http://localhost:5173")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const app = express();

// security + infra middleware
app.use(helmet());
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (CORS_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked"));
    },
    credentials: true,
  })
);
app.use(compression());
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
if (NODE_ENV !== "test") app.use(morgan("tiny"));

// simple health checks
app.get("/health", (_req, res) => res.json({ ok: true, env: NODE_ENV }));
app.get("/ping", (_req, res) => res.send("pong"));

// mount routers
app.use("/auth", authRouter);
app.use("/user", userRouter);

// 404
app.use((_req, res) => {
  res.status(404).json({ message: "Not found" });
});

// central error handler
app.use(errorHandler);

export default app;
