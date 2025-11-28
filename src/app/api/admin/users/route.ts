import { NextResponse, NextRequest } from 'next/server';
import { getDatabase } from '@/lib/db';
import crypto from 'crypto';

interface AdminUser {
  id: number;
  username: string;
  password_hash?: string;
  salt?: string;
  created_at: string;
  last_login?: string;
  is_active: boolean;
}

// Verify session token (simplified for demo - in production you'd validate against a sessions table)
function verifySession(request: NextRequest): boolean {
  const sessionToken = request.cookies.get('admin_session')?.value;
  return Boolean(sessionToken && sessionToken.length === 64);
}

// Hash password with salt
function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

// Generate random salt
function generateSalt(): string {
  return crypto.randomBytes(32).toString('hex');
}

// GET - List all admin users
export async function GET(request: NextRequest) {
  try {
    // Check authentication
    if (!verifySession(request)) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Get all admin users (excluding password data)
    const prepared = await db.prepare('SELECT id, username, created_at, last_login, is_active FROM admin_users ORDER BY created_at DESC');
    const users = await prepared.all() as AdminUser[];

    return NextResponse.json({ users });

  } catch (error) {
    console.error('Error fetching admin users:', error);
    return NextResponse.json(
      { error: 'Failed to fetch admin users' },
      { status: 500 }
    );
  }
}

// POST - Create new admin user
export async function POST(request: NextRequest) {
  try {
    // Check authentication
    if (!verifySession(request)) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { username, password } = await request.json();

    if (!username || !password) {
      return NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400 }
      );
    }

    if (password.length < 8) {
      return NextResponse.json(
        { error: 'Password must be at least 8 characters long' },
        { status: 400 }
      );
    }

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Check if user already exists
    const checkPrepared = await db.prepare('SELECT COUNT(*) as count FROM admin_users WHERE username = ?');
    const existingUser = await checkPrepared.bind(username).first() as { count: number };

    if (existingUser.count > 0) {
      return NextResponse.json(
        { error: 'Username already exists' },
        { status: 409 }
      );
    }

    // Generate salt and hash password
    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);

    // Create new admin user
    const prepared = await db.prepare(`
      INSERT INTO admin_users (username, password_hash, salt, created_at, is_active)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP, 1)
    `);
    
    const result = await prepared.bind(username, passwordHash, salt).run();

    if (!result.success) {
      return NextResponse.json(
        { error: 'Failed to create admin user' },
        { status: 500 }
      );
    }

    // Log admin creation
    const logPrepared = await db.prepare(`
      INSERT INTO admin_logs (action, data, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
    `);
    await logPrepared.bind(
      'admin_user_created',
      JSON.stringify({ username }),
      request.headers.get('x-forwarded-for') || 'unknown',
      request.headers.get('user-agent') || 'unknown'
    ).run();

    return NextResponse.json({
      success: true,
      message: 'Admin user created successfully',
      user: { id: result.meta.last_row_id, username }
    });

  } catch (error) {
    console.error('Error creating admin user:', error);
    return NextResponse.json(
      { error: 'Failed to create admin user' },
      { status: 500 }
    );
  }
}

// PATCH - Update admin user (activate/deactivate)
export async function PATCH(request: NextRequest) {
  try {
    // Check authentication
    if (!verifySession(request)) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { userId, is_active } = await request.json();

    if (!userId || is_active === undefined) {
      return NextResponse.json(
        { error: 'User ID and status are required' },
        { status: 400 }
      );
    }

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Update user status
    const prepared = await db.prepare('UPDATE admin_users SET is_active = ? WHERE id = ?');
    const result = await prepared.bind(is_active ? 1 : 0, userId).run();

    if (!result.success) {
      return NextResponse.json(
        { error: 'Failed to update user status' },
        { status: 500 }
      );
    }

    // Log status change
    const logPrepared = await db.prepare(`
      INSERT INTO admin_logs (action, data, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
    `);
    await logPrepared.bind(
      'admin_user_status_changed',
      JSON.stringify({ userId, is_active }),
      request.headers.get('x-forwarded-for') || 'unknown',
      request.headers.get('user-agent') || 'unknown'
    ).run();

    return NextResponse.json({
      success: true,
      message: `User ${is_active ? 'activated' : 'deactivated'} successfully`
    });

  } catch (error) {
    console.error('Error updating admin user:', error);
    return NextResponse.json(
      { error: 'Failed to update admin user' },
      { status: 500 }
    );
  }
}
