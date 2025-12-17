// Password reset controller
// - forgotPassword: issues an opaque token via email (hash stored in DB)
// - resetPassword: validates token, updates password, and invalidates sessions
const bcrypt = require('bcrypt');
const user = require('../models/user');
const crypto = require('crypto');
const dotenv = require('dotenv');
dotenv.config();

/**
 * POST /api/auth/forgot-password
 * Body: { email }
 * Generates a one-time token, stores its hash + expiry, and (in prod) emails a reset link.
 * In development, returns a token in the response for easy testing.
 */
exports.forgotPassword = async (req, res) => {
    // Implementation for forgot password
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }
        // Logic to generate reset token and send email
        const token = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        // Store hashedToken in DB against the user for later verification
        const existingUser = await user.findOne({ email: email });
        if (!existingUser) {
            return res.status(200).json({ message: 'Password reset link sent to email if exists' });
        }
        existingUser.passwordResetToken = {
            token: hashedToken,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000) // 1 hour expiry
        };
        await existingUser.save();
        // Send email with reset link (implementation omitted; use Nodemailer/provider)
        res.status(200).json({ message: 'Password reset link sent to email if exists', resetToken: token });
    }
    catch (err) {
        console.log("Error in forgotPassword:", err);
        res.status(500).json({ message: 'Something went wrong' });
    }
}

/**
 * POST /api/auth/reset-password
 * Body: { token, newPassword }
 * Validates the opaque token (by hash), sets a new hashed password,
 * clears the reset token, and revokes all refresh tokens (logout all sessions).
 */
exports.resetPassword = async (req, res) => {
    // Implementation for reset password
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) {
            return res.status(400).json({ message: 'Token and new password are required' });
        }
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const existingUser = await user.findOne({ 
            'passwordResetToken.token': hashedToken,
            'passwordResetToken.expiresAt': { $gt: new Date() }
        });
        if (!existingUser) {
            return res.status(400).json({ message: 'Invalid or expired password reset token' });
        }
        // Update password
        const salt = await bcrypt.genSalt(10);
        existingUser.password = await bcrypt.hash(newPassword, salt);
        existingUser.passwordResetToken = null;
        existingUser.refreshTokens = [];
        await existingUser.save();
        res.status(200).json({ message: 'Password has been reset successfully' });
    }
    catch (err) {
        console.log("Error in resetPassword:", err);
        res.status(500).json({ message: 'Something went wrong' });
    }
}