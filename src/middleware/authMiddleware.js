import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export const authenticateToken = (req, res, next) => {
    const token = req.cookies?.accessToken;

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.userRoles = decoded.roles;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid or expired token' });
    }
};

// Role-based authorization middleware
export const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.userRoles || !roles.some(role => req.userRoles?.includes(role))) {
            return res.status(403).json({ message: 'Insufficient permissions' });
        }
        next();
    };
};