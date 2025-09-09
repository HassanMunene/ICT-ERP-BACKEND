import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../prisma/index.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Token generation functions
const generateAccessToken = (userId, email) => {
    return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });
};

export const registerUser = async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;

        // Check if user exists
        const existingUser = await prisma.user.findUnique({
            where: { email }
        });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Create user WITHOUT roles (admin will assign later)
        const user = await prisma.user.create({
            data: {
                email: email,
                passwordHash: passwordHash,
                firstName: firstName,
                lastName: lastName,
                status: 'PENDING_APPROVAL',
            },
            include: {
                department: true
            }
        });

        // Generate basic token (user won't have dashboard access until approved)
        const accessToken = generateAccessToken(user.id, user.email);

        // Set cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'None',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        // Return user data without password
        const { passwordHash: _, ...userWithoutPassword } = user;
        res.status(201).json({
            message: 'Registration successful. Please wait for admin approval.',
            user: userWithoutPassword,
            accessToken,
            requiresApproval: true
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}