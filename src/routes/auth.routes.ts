// src/routes/auth.routes.ts
import { Router } from "express";
import * as Auth from "../controllers/auth.controller.js";

const router = Router();

router.post("/sign-up", Auth.signUp);
router.post("/sign-in", Auth.signIn);
router.post("/refresh", Auth.refresh);
router.post("/logout", Auth.logout);
router.post("/logout-all", Auth.logoutAll);
router.post("/verify-email", Auth.verifyEmail);
router.post("/resend-verification", Auth.resendVerification);
router.post("/password-reset/request", Auth.passwordResetRequest);
router.post("/password-reset/verify", Auth.passwordResetVerify);
router.post("/password-reset/confirm", Auth.passwordResetConfirm);

export default router;
