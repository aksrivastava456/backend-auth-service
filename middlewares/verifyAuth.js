// Auth guard middleware: verifies the Bearer access token
// - Expects Authorization: Bearer <JWT>
// - On success, attaches payload to req.user { userId, role, iat, exp }
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

module.exports = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'Authorization header missing' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'You need to login.' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_KEY);
        req.user = decoded;
        next();
    }
    catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};