import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
    console.log('Starting seed...');

    // 1. Create essential roles
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

    // 2. Create departments
    const itDepartment = await prisma.department.upsert({
        where: { name: 'IT' },
        update: {},
        create: {
            name: 'IT',
        },
    });

    await prisma.department.createMany({
        data: [
            { name: 'Finance' },
            { name: 'Operations' },
            { name: 'Sales' },
            { name: 'Marketing' },
        ],
        skipDuplicates: true,
    });

    // 3. Create admin user with ACTIVE status
    const adminUser = await prisma.user.upsert({
        where: { email: 'admin@company.com' },
        update: {
            status: 'ACTIVE',
            departmentId: itDepartment.id,
            passwordHash: await bcrypt.hash('admin123', 12),
            firstName: 'Admin',
            lastName: 'User'
        },
        create: {
            email: 'admin@company.com',
            passwordHash: await bcrypt.hash('admin123', 12),
            firstName: 'Admin',
            lastName: 'User',
            status: 'ACTIVE',
            department: {
                connect: { id: itDepartment.id }
            },
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
            },
            department: true
        }
    });

    console.log('Admin user created/updated:', {
        email: adminUser.email,
        status: adminUser.status,
        roles: adminUser.userRoles.map(ur => ur.role.name),
        department: adminUser.department?.name
    });

    // 4. Create some basic permissions (optional but recommended)
    const permissions = [
        { code: 'USER.MANAGE', description: 'Manage users' },
        { code: 'ROLE.MANAGE', description: 'Manage roles' },
        { code: 'PROJECT.READ', description: 'View projects' },
        { code: 'PROJECT.MANAGE', description: 'Manage projects' },
        { code: 'FINANCE.READ', description: 'View financial data' },
        { code: 'FINANCE.MANAGE', description: 'Manage financial data' },
        { code: 'CRM.READ', description: 'View CRM data' },
        { code: 'CRM.MANAGE', description: 'Manage CRM data' },
    ];

    for (const permissionData of permissions) {
        await prisma.permission.upsert({
            where: { code: permissionData.code },
            update: {},
            create: permissionData
        });
    }

    console.log('Permissions created');

    // 5. Assign all permissions to ADMIN role (optional)
    const allPermissions = await prisma.permission.findMany();

    for (const permission of allPermissions) {
        await prisma.rolePermission.upsert({
            where: {
                roleId_permissionId: {
                    roleId: adminRole.id,
                    permissionId: permission.id
                }
            },
            update: {},
            create: {
                roleId: adminRole.id,
                permissionId: permission.id
            }
        });
    }

    console.log('All permissions assigned to ADMIN role');

    console.log('Seed completed successfully!');
    console.log('Admin login credentials:');
    console.log('Email: admin@company.com');
    console.log('Password: admin123');
    console.log('Status: ACTIVE');
}

main()
    .catch((e) => {
        console.error('Seed error:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });