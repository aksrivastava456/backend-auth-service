// Issues a new access token using a valid refresh token from cookie
// - Verifies and rotates the refresh token (hash stored in DB)
// - Sets a new refresh cookie and returns a fresh access token in JSON
const jwt = require('jsonwebtoken');
const user = require('../models/user');
const crypto = require('crypto');
const dotenv = require('dotenv');
dotenv.config();

exports.refreshToken = async (req, res) => {
    try {
        // Read refresh token from httpOnly cookie (requires cookie-parser)
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({ message: 'Refresh token missing' });
        }
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY);
        const existingUser = await user.findById(decoded.userId);
        if (!existingUser) {
            return res.status(401).json({ message: 'Invalid refresh token' });
        }
        const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
        // Ensure the incoming token matches a stored (hashed) token for this user
        const tokenExists = existingUser.refreshTokens && existingUser.refreshTokens.find(rt => rt.token === hashedToken);
        if (!tokenExists) {
            existingUser.refreshTokens = [];
            await existingUser.save();
            return res.status(401).json({ message: 'Session expired, please login again' });
        }
        // Rotate: remove old token hash
        existingUser.refreshTokens = existingUser.refreshTokens.filter(rt => rt.token !== hashedToken);
        const newAccessToken = jwt.sign(
            { userId: existingUser._id, role: existingUser.role }, process.env.JWT_ACCESS_KEY, { expiresIn: '15m' }
        );
        const newRefreshToken = jwt.sign(
            { userId: existingUser._id, role: existingUser.role }, process.env.JWT_REFRESH_KEY, { expiresIn: '7d' }
        );
        existingUser.refreshTokens.push({
            token: crypto.createHash('sha256').update(newRefreshToken).digest('hex'),
            userId: existingUser._id,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });
        await existingUser.save();
        // Issue a new refresh cookie
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        // Return fresh access token to use as Bearer token
        res.status(200).json({ accessToken: newAccessToken });
    }
    catch (err) {
        console.log("Error in refreshToken:", err);
        return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }
}