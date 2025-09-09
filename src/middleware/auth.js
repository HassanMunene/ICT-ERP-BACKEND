import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export interface AuthenticatedRequest extends Request {
    userId?: string;
    userRoles?: string[];
}

export const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const token = req.cookies.accessToken || req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; email: string; roles: string[] };
        req.userId = decoded.userId;
        req.userRoles = decoded.roles;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid or expired token' });
    }
};

// Role-based authorization middleware
export const requireRole = (roles: string[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
        if (!req.userRoles || !roles.some(role => req.userRoles?.includes(role))) {
            return res.status(403).json({ message: 'Insufficient permissions' });
        }
        next();
    };
};