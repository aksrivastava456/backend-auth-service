// User model
// - Stores username/email/password and role for RBAC
// - Persists hashed refresh tokens for rotation during refresh flow
const mongoose = require('mongoose');

const emailVerificationSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    }
}, { timestamps: true });

// Embedded subdocument for storing hashed refresh tokens
const refreshTokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    }
}, { timestamps: true }
);

const passwordResetTokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    }
}, { timestamps: true });

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type : String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    emailVerification: {
        type: emailVerificationSchema,
        default: null
    },
    refreshTokens: [refreshTokenSchema],
    passwordResetToken: {
        type: passwordResetTokenSchema,
        default: null
    }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);