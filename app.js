// Entry point for the Auth Service API
// - Boots Express, connects to MongoDB, mounts routers and common middleware
// - Exposes health/root route and a catch-all 404 handler
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const app = express();

// Parses cookies from incoming requests so controllers can read req.cookies
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// Routers
const authRouter = require('./routes/authRouter');
const protectedRouter = require('./routes/protectedRouter');
const errorsController = require('./controllers/errors');

// Body parsers and static assets
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Simple root route for a quick service check
app.get('/', (req, res) => {
    res.send('Welcome to the Auth Service');
});

// Mount API routes
app.use('/api/auth', authRouter);
app.use('/api/test', protectedRouter);
// 404 for all other unmatched routes
app.use(errorsController.pageNotFound);

const PORT = process.env.PORT;
const DB_PATH = process.env.DB;

// Connect to MongoDB then start the HTTP server
mongoose.connect(DB_PATH).then(() => {
    app.listen(PORT, () => {
        console.log(`Auth Service is running on http://localhost:${PORT}`);
    })
}).catch(err => {
    console.error('Database connection failed:', err);
});