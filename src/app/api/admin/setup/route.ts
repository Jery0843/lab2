import { NextResponse, NextRequest } from 'next/server';
import { getDatabase } from '@/lib/db';
import {
  hashPassword,
  generateSalt,
  getClientIP,
  getSecurityHeaders,
  sanitizeInput,
  isValidUsername,
  isStrongPassword,
  createSecurityLog
} from '@/lib/security';

// POST - Setup initial admin user
export async function POST(request: NextRequest) {
  try {
    const { username, password, setupKey } = await request.json();
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Sanitize inputs
    const cleanUsername = sanitizeInput(username || '');
    const cleanPassword = password || '';
    const cleanSetupKey = sanitizeInput(setupKey || '');

    // Check for secure setup key from environment variables
    const validSetupKey = process.env.ADMIN_SETUP_KEY;
    if (!validSetupKey) {
      return NextResponse.json(
        { error: 'Admin setup is disabled - no setup key configured' },
        { status: 503 }
      );
    }
    
    if (cleanSetupKey !== validSetupKey) {
      // Log invalid setup attempt
      const db = getDatabase();
      if (db) {
        const logStmt = await db.prepare(`
          INSERT INTO admin_logs (action, data, ip_address, user_agent)
          VALUES (?, ?, ?, ?)
        `);
        await logStmt.bind(
          'setup_failure',
          createSecurityLog({
            type: 'login_failure',
            ip: clientIP,
            userAgent,
            username: cleanUsername,
            details: { reason: 'invalid_setup_key' }
          }),
          clientIP,
          userAgent
        ).run();
      }
      
      return NextResponse.json(
        { error: 'Invalid setup key' },
        { status: 401, headers: getSecurityHeaders() }
      );
    }

    if (!cleanUsername || !cleanPassword) {
      return NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400, headers: getSecurityHeaders() }
      );
    }

    // Validate username format
    if (!isValidUsername(cleanUsername)) {
      return NextResponse.json(
        { error: 'Username must be 3-20 characters long and contain only letters, numbers, underscores, and hyphens' },
        { status: 400, headers: getSecurityHeaders() }
      );
    }

    // Validate password strength
    const passwordValidation = isStrongPassword(cleanPassword);
    if (!passwordValidation.valid) {
      return NextResponse.json(
        { error: passwordValidation.errors.join('. ') },
        { status: 400, headers: getSecurityHeaders() }
      );
    }

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Check if admin user already exists
    const checkPrepared = await db.prepare('SELECT COUNT(*) as count FROM admin_users WHERE username = ?');
    const existingUser = await checkPrepared.bind(cleanUsername).first() as { count: number };

    if (existingUser.count > 0) {
      return NextResponse.json(
        { error: 'Admin user already exists' },
        { status: 409, headers: getSecurityHeaders() }
      );
    }

    // Generate salt and hash password
    const salt = generateSalt();
    const passwordHash = hashPassword(cleanPassword, salt);

    // Create admin user
    const prepared = await db.prepare(`
      INSERT INTO admin_users (username, password_hash, salt, created_at, is_active)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP, 1)
    `);
    
    const result = await prepared.bind(cleanUsername, passwordHash, salt).run();

    if (!result.success) {
      return NextResponse.json(
        { error: 'Failed to create admin user' },
        { status: 500, headers: getSecurityHeaders() }
      );
    }

    // Log admin creation
    const logPrepared = await db.prepare(`
      INSERT INTO admin_logs (action, data, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
    `);
    await logPrepared.bind(
      'admin_user_created',
      createSecurityLog({
        type: 'login_success',
        ip: clientIP,
        userAgent,
        username: cleanUsername,
        details: { action: 'user_created' }
      }),
      clientIP,
      userAgent
    ).run();

    return NextResponse.json({
      success: true,
      message: 'Admin user created successfully',
      user: { username: cleanUsername }
    }, { headers: getSecurityHeaders() });

  } catch (error) {
    console.error('Error creating admin user:', error);
    return NextResponse.json(
      { error: 'Failed to create admin user' },
      { status: 500, headers: getSecurityHeaders() }
    );
  }
}

// GET - Check if admin users exist
export async function GET() {
  try {
    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503, headers: getSecurityHeaders() }
      );
    }

    // Check if any admin users exist
    const prepared = await db.prepare('SELECT COUNT(*) as count FROM admin_users WHERE is_active = 1');
    const result = await prepared.first() as { count: number };

    return NextResponse.json({
      hasAdminUser: result.count > 0,
      adminCount: result.count
    }, { headers: getSecurityHeaders() });

  } catch (error) {
    console.error('Error checking admin users:', error);
    return NextResponse.json(
      { error: 'Failed to check admin users' },
      { status: 500, headers: getSecurityHeaders() }
    );
  }
}
