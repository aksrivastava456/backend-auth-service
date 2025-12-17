// Demo routes to exercise auth + role guards
const express = require('express');
const verifyAuth = require('../middlewares/verifyAuth');
const verifyRole = require('../middlewares/verifyRole');

const testRouter = express.Router();

testRouter.get('/admin', verifyAuth, verifyRole('admin'), (req, res) => {
    res.status(200).json({ message: 'Welcome Admin', user: req.user });
});

testRouter.get('/user', verifyAuth, verifyRole('admin', 'user'), (req, res) => {
    res.status(200).json({ message: 'Welcome User', user : req.user });
});

module.exports = testRouter;