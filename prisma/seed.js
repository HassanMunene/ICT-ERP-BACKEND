import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
    console.log('Starting seed...');

    // 1. Create essential roles (without permissions)
    const adminRole = await prisma.role.upsert({
        where: { name: 'ADMIN' },
        update: {},
        create: {
            name: 'ADMIN',
            description: 'System Administrator with full access',
            scope: 'SYSTEM',
        },
    });

    const userRole = await prisma.role.upsert({
        where: { name: 'USER' },
        update: {},
        create: {
            name: 'USER',
            description: 'Regular user with basic access',
            scope: 'MODULE',
        },
    });

    // 2. Create some departments (optional)
    const departments = await prisma.department.createMany({
        data: [
            { name: 'IT' },
            { name: 'Finance' },
            { name: 'Operations' },
            { name: 'Sales' },
            { name: 'Marketing' },
        ],
        skipDuplicates: true,
    });

    // Add this to your seed function
    const adminUser = await prisma.user.create({
        data: {
            email: 'admin@company.com',
            passwordHash: await bcrypt.hash('admin123', 12),
            firstName: 'Admin',
            lastName: 'User',
            userRoles: {
                create: {
                    role: { connect: { id: adminRole.id } }
                }
            }
        },
        include: {
            userRoles: {
                include: {
                    role: true
                }
            }
        }
    });

    console.log('Admin user created:', adminUser.email);

    console.log('Seed completed successfully!');
    console.log('Created roles:', { adminRole, userRole });
}

main()
    .catch((e) => {
        console.error('Seed error:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });