import express from 'express';
import { registerUser, loginUser } from '../controllers/authController.js';

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
// router.post('/refresh-token', authController.refreshToken);
// router.post('/logout', authController.logout);
// router.get('/me', authController.getCurrentUser);

export default router;