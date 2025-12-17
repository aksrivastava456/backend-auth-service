// Role guard middleware: ensures the authenticated user has one of the allowed roles
// Usage: verifyRole('admin') or verifyRole('admin','user') after verifyAuth
module.exports = (...allowedRoles) => {
    return (req, res, next) => {
        const role = req.user.role;
        if (!role) {
            return res.status(403).json({ message: 'Role information missing' });
        }
        if (!allowedRoles.includes(role)) {
            return res.status(403).json({ message: 'Unauthorized Access' });
        }
        next();
    }
}