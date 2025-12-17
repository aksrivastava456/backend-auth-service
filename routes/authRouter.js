// Auth endpoints router
// - Registration, login, token refresh, and logout
const express = require('express');
const authRouter = express.Router();

const authController = require('../controllers/authController');
const refreshController = require('../controllers/refreshController');
const passwordController = require('../controllers/passwordController');

// Create account and send email verification token
authRouter.post('/register', authController.registerUser);
// Verify email using the token sent during registration
authRouter.post('/verify-email', authController.verifyEmail);
// Authenticate user and set refresh token cookie
authRouter.post('/login', authController.loginUser);
// Rotate refresh token and issue a new access token
authRouter.post('/refresh-token', refreshController.refreshToken);
// Clear refresh cookie and revoke the specific refresh token
authRouter.post('/logout', authController.logoutUser);
// Send password reset link (opaque token) to the user's email
authRouter.post('/forgot-password', passwordController.forgotPassword);
// Reset password using the provided reset token
authRouter.post('/reset-password', passwordController.resetPassword);

module.exports = authRouter;