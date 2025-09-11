import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

import { errorHandler } from './middleware/errorMiddleware.js';
import authRoutes from './routes/authRoutes.js';

// Load env variables;
dotenv.config();
const PORT = process.env.PORT || 5000;

const app = express();

const allowedOrigins = [
    'https://ict-erp.vercel.app',
    'http://localhost:5173'
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origins eg mobile apps, curl and postman
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        } else {
            return callback(new Error("Not allowed by CORS"));
        }
    },
    confidentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
}));

//parse JSON bodies
app.use(express.json());
// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));
// Parse URL-encoded bodies
app.use(cookieParser());

app.use('/api/auth', authRoutes);


// Basic Route to ensure our endpoint is working.
app.get('/', (req, res) => {
    res.json({ message: 'Welcome to the ICT ERP API!' });
});

// 404 for undefined routes
app.use('/{*any}', (req, res) => {
    res.status(404).json({ message: 'API endpoint not found' });
});

// Central Error Handler this Must be last
app.use(errorHandler);


// start the server
app.listen(PORT, () => {
    console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});





