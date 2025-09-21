import http from "http";
import dotenv from "dotenv";

dotenv.config();

import app from "./app.js";

const PORT = Number(4000);

const server = http.createServer(app);

server.listen(PORT, () => {
  console.log(`server ready on port ${PORT}`);
});

// graceful shutdown
const shutdown = (signal: string) => {
  console.log(`\n${signal} received — closing server...`);
  server.close((err) => {
    if (err) {
      console.error("Error during server close:", err);
      process.exit(1);
    }
    console.log("HTTP server closed. Bye! 👋");
    process.exit(0);
  });
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// catch unhandled rejections/exceptions to avoid silent crashes
process.on("unhandledRejection", (reason) => {
  // eslint-disable-next-line no-console
  console.error("Unhandled Rejection:", reason);
});
process.on("uncaughtException", (err) => {
  // eslint-disable-next-line no-console
  console.error("Uncaught Exception:", err);
  shutdown("uncaughtException");
});
