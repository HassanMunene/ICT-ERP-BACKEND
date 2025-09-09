import express from 'express';
import { registerUser } from '../controllers/authController.js';

const router = express.Router();

router.post('/register', registerUser);
// router.post('/login', authController.login);
// router.post('/refresh-token', authController.refreshToken);
// router.post('/logout', authController.logout);
// router.get('/me', authController.getCurrentUser);

export default router;