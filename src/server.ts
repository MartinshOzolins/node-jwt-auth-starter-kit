import app from "./app.js";
import "dotenv/config";

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`Server ready on port ${PORT}`);
});

// graceful shutdown
const shutdown = (signal: string) => {
  console.log(`\n${signal} received — closing server...`);
  server.close((err?: Error) => {
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
  console.error("Unhandled Rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  shutdown("uncaughtException");
});
