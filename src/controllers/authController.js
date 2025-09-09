import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../prisma/index.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Token generation functions
const generateAccessToken = (userId, email, roles) => {
    return jwt.sign({ userId, email, roles }, JWT_SECRET, { expiresIn: '30d' });
};

export const registerUser = async (req, res) => {
    try {
        const { email, password, firstName, lastName, departmentId, roles } = req.body;

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

        // Create user with roles
        const user = await prisma.user.create({
            data: {
                email: email,
                passwordHash: passwordHash,
                firstName: firstName,
                lastName: lastName,
                departmentId: departmentId,
                userRoles: {
                    create: roles.map((roleId) => ({
                        role: { connect: { id: roleId } }
                    }))
                }
            },
            include: {
                userRoles: {
                    include: {
                        role: true
                    }
                },
                department: true
            }
        });

        // Generate tokens
        const userRoles = user.userRoles.map(ur => ur.role.name);
        const accessToken = generateAccessToken(user.id, user.email, userRoles);

        // Set cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'None',
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        // Return user data without password and include tokens in response
        const { passwordHash: _, ...userWithoutPassword } = user;
        res.status(201).json({
            message: 'User registered successfully',
            user: userWithoutPassword,
            accessToken
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// export const authController = {


//     // Login user
//     async login(req: Request, res: Response) {
//         try {
//             const { email, password } = req.body;

//             // Find user with roles and department
//             const user = await prisma.user.findUnique({
//                 where: { email },
//                 include: {
//                     userRoles: {
//                         include: {
//                             role: true
//                         }
//                     },
//                     department: true,
//                     employee: true,
//                     contractor: true,
//                     marketer: true
//                 }
//             });

//             if (!user || user.status !== UserStatus.ACTIVE) {
//                 return res.status(401).json({ message: 'Invalid credentials or inactive account' });
//             }

//             // Verify password
//             const isValidPassword = await bcrypt.compare(password, user.passwordHash);
//             if (!isValidPassword) {
//                 return res.status(401).json({ message: 'Invalid credentials' });
//             }

//             // Generate tokens
//             const userRoles = user.userRoles.map(ur => ur.role.name);
//             const accessToken = generateAccessToken(user.id, user.email, userRoles);
//             const refreshToken = generateRefreshToken(user.id);

//             // Store refresh token in database
//             await prisma.refreshToken.create({
//                 data: {
//                     token: refreshToken,
//                     userId: user.id,
//                     expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
//                 }
//             });

//             // Set cookies
//             res.cookie('accessToken', accessToken, {
//                 httpOnly: true,
//                 secure: process.env.NODE_ENV === 'production',
//                 sameSite: 'strict',
//                 maxAge: 15 * 60 * 1000
//             });

//             res.cookie('refreshToken', refreshToken, {
//                 httpOnly: true,
//                 secure: process.env.NODE_ENV === 'production',
//                 sameSite: 'strict',
//                 maxAge: 7 * 24 * 60 * 60 * 1000
//             });

//             // Return user data without password
//             const { passwordHash, ...userWithoutPassword } = user;
//             res.json({
//                 message: 'Login successful',
//                 user: userWithoutPassword,
//                 accessToken,
//                 refreshToken
//             });

//         } catch (error) {
//             console.error('Login error:', error);
//             res.status(500).json({ message: 'Internal server error' });
//         }
//     },

//     // Refresh token
//     async refreshToken(req: Request, res: Response) {
//         try {
//             const refreshToken = req.cookies.refreshToken;

//             if (!refreshToken) {
//                 return res.status(401).json({ message: 'Refresh token required' });
//             }

//             // Verify refresh token
//             const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as { userId: string };

//             // Check if refresh token exists in database
//             const storedToken = await prisma.refreshToken.findUnique({
//                 where: { token: refreshToken },
//                 include: { user: true }
//             });

//             if (!storedToken || storedToken.expiresAt < new Date()) {
//                 return res.status(401).json({ message: 'Invalid or expired refresh token' });
//             }

//             // Get user roles
//             const user = await prisma.user.findUnique({
//                 where: { id: payload.userId },
//                 include: {
//                     userRoles: {
//                         include: {
//                             role: true
//                         }
//                     }
//                 }
//             });

//             if (!user || user.status !== UserStatus.ACTIVE) {
//                 return res.status(401).json({ message: 'User not found or inactive' });
//             }

//             const userRoles = user.userRoles.map(ur => ur.role.name);
//             const newAccessToken = generateAccessToken(user.id, user.email, userRoles);

//             // Update access token cookie
//             res.cookie('accessToken', newAccessToken, {
//                 httpOnly: true,
//                 secure: process.env.NODE_ENV === 'production',
//                 sameSite: 'strict',
//                 maxAge: 15 * 60 * 1000
//             });

//             res.json({
//                 message: 'Token refreshed successfully',
//                 accessToken: newAccessToken
//             });

//         } catch (error) {
//             console.error('Refresh token error:', error);
//             res.status(401).json({ message: 'Invalid refresh token' });
//         }
//     },

//     // Logout
//     async logout(req: Request, res: Response) {
//         try {
//             const refreshToken = req.cookies.refreshToken;

//             // Delete refresh token from database
//             if (refreshToken) {
//                 await prisma.refreshToken.deleteMany({
//                     where: { token: refreshToken }
//                 });
//             }

//             // Clear cookies
//             res.clearCookie('accessToken');
//             res.clearCookie('refreshToken');

//             res.json({ message: 'Logout successful' });

//         } catch (error) {
//             console.error('Logout error:', error);
//             res.status(500).json({ message: 'Internal server error' });
//         }
//     },

//     // Get current user
//     async getCurrentUser(req: Request, res: Response) {
//         try {
//             // This assumes you have authentication middleware that adds user to request
//             const userId = (req as any).userId;

//             const user = await prisma.user.findUnique({
//                 where: { id: userId },
//                 include: {
//                     userRoles: {
//                         include: {
//                             role: true
//                         }
//                     },
//                     department: true,
//                     employee: true,
//                     contractor: true,
//                     marketer: true
//                 }
//             });

//             if (!user) {
//                 return res.status(404).json({ message: 'User not found' });
//             }

//             const { passwordHash, ...userWithoutPassword } = user;
//             res.json(userWithoutPassword);

//         } catch (error) {
//             console.error('Get current user error:', error);
//             res.status(500).json({ message: 'Internal server error' });
//         }
//     }
// };