// Auth controller: registration, login, logout
// - Registers users with a hashed password
// - Issues/rotates JWT access and refresh tokens
// - Stores hashed refresh tokens on the user document
const user = require("../models/user");
const errorsController = require("./errors");
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const jwt = require('jsonwebtoken');
// cookie-parser is registered at app-level; no need to import here
const dotenv = require('dotenv');
dotenv.config();

/**
 * POST /api/auth/register
 * Body: { username, email, password, role? }
 * Creates a new user (role defaults to 'user'), hashing the password.
 */
exports.registerUser = async (req, res, next) => {
    try {
        let { username, email, password, role } = req.body;
        if (!username || !email || !password ) {
            return res.status(400).json({ message: 'Some fields are missing' });
        }

        // Ensure email and username are unique
        const existingEmail = await user.findOne({ email: email });
        if (existingEmail) {
            return errorsController.somethingWentWrong(req, res, next);
        }
        const existingUsername = await user.findOne({ username: username });
        if (existingUsername) {
            return errorsController.usernameTaken(req, res, next);
        }

        // Hash password with a reasonable cost factor
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new user({
            username: username,
            email: email,
            password: hashedPassword,
            role: role || 'user',
            refreshTokens: []
        });
        await newUser.save();

        const rawVerifyToken = crypto.randomBytes(32).toString('hex');
        const hashedVerifyToken = crypto.createHash('sha256').update(rawVerifyToken).digest('hex');
        newUser.emailVerification = {
            token: hashedVerifyToken,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours expiry
        };
        await newUser.save();
        // Send verification email with rawVerifyToken (implementation omitted)

        // Do not include sensitive fields in the response
        res.status(201).json({ message: 'User registered. Please verify your email.', token: rawVerifyToken });
    }
    catch (err) {
        console.log("Error in registerUser:", err);
        errorsController.somethingWentWrong(req, res, next);
    }
}

exports.verifyEmail = async (req, res, next) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(400).json({ message: 'Verification token is required' });
        }
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        const existingUser = await user.findOne({ 
            'emailVerification.token': hashedToken,
            'emailVerification.expiresAt': { $gt: new Date() }
        });
        if (!existingUser) {
            return res.status(400).json({ message: 'Invalid or expired verification token' });
        }
        existingUser.emailVerification = null;
        existingUser.isVerified = true;
        await existingUser.save();
        res.status(200).json({ message: 'Email verified successfully' });
    }
    catch (err) {
        console.log("Error in verifyEmail:", err);
        errorsController.somethingWentWrong(req, res, next);
    }
}

/**
 * POST /api/auth/login
 * Body: { emailOrUsername, password }
 * Verifies credentials, sets httpOnly refresh cookie, returns an access token.
 */
exports.loginUser = async (req, res, next) => {
    try {
        const { emailOrUsername, password } = req.body;
        if (!emailOrUsername || !password) {
            return res.status(400).json({ message: 'Some fields are missing' });
        }
        const existingUser = await user.findOne({ 
            $or: [ { email: emailOrUsername }, { username: emailOrUsername } ] 
        });
        if (!existingUser) {
            return errorsController.emailOrPasswordIncorrect(req, res, next);
        }
        if (!existingUser.isVerified) {
            return res.status(403).json({ message: 'Please verify your email before logging in.' });
        }
        // Verify password
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if (!isMatch) {
            return errorsController.emailOrPasswordIncorrect(req, res, next);
        }

        // Short-lived access token for Authorization header
        const accessToken = jwt.sign(
            { userId: existingUser._id, role: existingUser.role }, process.env.JWT_ACCESS_KEY, { expiresIn: '15m' }
        );

        // Long-lived refresh token stored as httpOnly cookie and hashed in DB
        const refreshToken = jwt.sign(
            { userId: existingUser._id, role: existingUser.role }, process.env.JWT_REFRESH_KEY, { expiresIn: '7d' }
        );

        const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');

        // Send refresh token as httpOnly cookie (not accessible to JS)
        // Note: set secure:true only in production; Lax helps mitigate CSRF
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        existingUser.refreshTokens.push({
            token: hashedToken,
            userId: existingUser._id,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });
        await existingUser.save();
        
        // Return access token in body for API clients to use as Bearer token
        res.status(200).json({
            message: 'Login successful',
            accessToken: accessToken,
        });
    }
    catch (err) {
        console.log("Error in loginUser:", err);
        errorsController.somethingWentWrong(req, res, next);
    }
}

/**
 * POST /api/auth/logout
 * Clears refresh token cookie and removes the stored hashed token.
 */
exports.logoutUser = async (req, res, next) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(200).json({ message: 'Logout successful' });
        }
        const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
        await user.updateOne(
            { 'refreshTokens.token': hashedToken },
            { $pull: { refreshTokens: { token: hashedToken } } }
        );
        // Clear the refresh cookie
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax'
        });
        res.status(200).json({ message: 'Logout successful' });
    }
    catch (err) {
        console.log("Error in logoutUser:", err);
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax'
        });
        res.status(200).json({ message: 'Logout successful' });
    }
}