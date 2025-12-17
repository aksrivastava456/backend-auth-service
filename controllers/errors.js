// Centralized tiny helpers for sending consistent error responses
// Keep these pure (no side effects) and always return to prevent double sends
exports.pageNotFound = (req, res, next) => {
    res.status(404).json({ message: 'Page Not Found' });
};

/** 401 when credentials are wrong */
exports.emailOrPasswordIncorrect = (req, res, next) => {
    res.status(401).json({ message: 'Email or Password is incorrect' });
};

/** 403 when the user is authenticated but forbidden by role/policy */
exports.unauthorizedAccess = (req, res, next) => {
    res.status(403).json({ message: 'Unauthorized Access' });
};

/** Generic 409 for business-rule conflicts */
exports.somethingWentWrong = (req, res, next) => {
    res.status(409).json({ message: 'Something went wrong, please try again' });
};

/** 409 when the username is already taken */
exports.usernameTaken = (req, res, next) => {
    res.status(409).json({ message: 'Username is already taken, try a new one' });
};
