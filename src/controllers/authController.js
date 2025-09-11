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

export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const user = await prisma.user.findUnique({
            where: { email },
            include: {
                userRoles: {
                    include: {
                        role: true
                    }
                },
                department: true,
                employee: true,
                contractor: true,
                marketer: true
            }
        });

        if (!user) {
            return res.status(401).json({
                message: 'Invalid email or password'
            });
        }

        // Check if user is approved
        if (user.status !== 'ACTIVE') {
            return res.status(403).json({
                message: 'Account pending approval. Please contact administrator.',
                requiresApproval: true
            });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.passwordHash);
        if (!isValidPassword) {
            return res.status(401).json({
                message: 'Invalid email or password'
            });
        }

        // Get user roles
        const userRoles = user.userRoles.map(ur => ur.role.name);

        // Generate tokens
        const accessToken = generateAccessToken(user.id, user.email, userRoles);

        // Set HTTP-only cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'None',
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        // Return user data without password
        const { passwordHash, ...userWithoutPassword } = user;

        res.json({
            message: 'Login successful',
            user: {
                ...userWithoutPassword,
                roles: userRoles
            },
            accessToken,
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            message: 'Internal server error'
        });
    }
};