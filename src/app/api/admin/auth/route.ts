import { NextResponse, NextRequest } from 'next/server';
import { getDatabase } from '@/lib/db';
import {
  hashPassword,
  generateSalt,
  verifyPassword,
  generateSecureToken,
  getClientIP,
  isValidSessionToken,
  getSecurityHeaders,
  sanitizeInput,
  createSecurityLog,
  getSessionCookieOptions,
  SECURITY_CONFIG
} from '@/lib/security';

interface AdminUser {
  id: number;
  username: string;
  password_hash: string;
  salt: string;
  created_at: string;
  last_login?: string;
  is_active: boolean;
}

// POST - Admin login
export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    // Sanitize inputs
    const cleanUsername = sanitizeInput(username || '');
    const cleanPassword = password || '';

    if (!cleanUsername || !cleanPassword) {
      const response = NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400, headers: getSecurityHeaders() }
      );
      return response;
    }

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Check rate limiting
    const rateLimitStmt = await db.prepare('SELECT failed_attempts, locked_until FROM admin_rate_limit WHERE ip_address = ?');
    const rateLimitCheck = await rateLimitStmt.bind(clientIP).first() as { failed_attempts: number; locked_until: string } | null;

    if (rateLimitCheck) {
      const now = new Date();
      const lockedUntil = rateLimitCheck.locked_until ? new Date(rateLimitCheck.locked_until) : null;
      
      if (lockedUntil && now < lockedUntil) {
        const remainingTime = Math.ceil((lockedUntil.getTime() - now.getTime()) / 60000);
        
        // Log rate limit exceeded
        const logStmt = await db.prepare(`
          INSERT INTO admin_logs (action, data, ip_address, user_agent)
          VALUES (?, ?, ?, ?)
        `);
        await logStmt.bind(
          'rate_limit_exceeded',
          createSecurityLog({
            type: 'rate_limit_exceeded',
            ip: clientIP,
            userAgent,
            username: cleanUsername,
            details: { remainingTime }
          }),
          clientIP,
          userAgent
        ).run();
        
        return NextResponse.json(
          { error: `Too many failed attempts. Try again in ${remainingTime} minutes.` },
          { status: 429, headers: getSecurityHeaders() }
        );
      }
    }

    // Get admin user from database
    const prepared = await db.prepare('SELECT * FROM admin_users WHERE username = ? AND is_active = 1');
    const user = await prepared.bind(cleanUsername).first() as AdminUser | null;

    if (!user) {
      // Simulate password verification to prevent timing attacks
      const fakeSalt = generateSalt();
      hashPassword(cleanPassword, fakeSalt);
      
      // Log failed login attempt
      const logStmt = await db.prepare(`
        INSERT INTO admin_logs (action, data, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
      `);
      await logStmt.bind(
        'login_failure',
        createSecurityLog({
          type: 'login_failure',
          ip: clientIP,
          userAgent,
          username: cleanUsername,
          details: { reason: 'user_not_found' }
        }),
        clientIP,
        userAgent
      ).run();
      
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401, headers: getSecurityHeaders() }
      );
    }

    // Verify password
    if (!verifyPassword(cleanPassword, user.password_hash, user.salt)) {
      // Increment failed attempts
      const failedAttempts = rateLimitCheck ? rateLimitCheck.failed_attempts + 1 : 1;
      const lockedUntil = failedAttempts >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS ? 
        new Date(Date.now() + SECURITY_CONFIG.LOCKOUT_DURATION).toISOString() : null;
      
      const rateLimitUpdateStmt = await db.prepare(`
        INSERT OR REPLACE INTO admin_rate_limit (ip_address, failed_attempts, locked_until, last_attempt)
        VALUES (?, ?, ?, datetime('now'))
      `);
      await rateLimitUpdateStmt.bind(clientIP, failedAttempts, lockedUntil).run();
      
      // Log failed login attempt
      const logStmt = await db.prepare(`
        INSERT INTO admin_logs (action, data, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
      `);
      await logStmt.bind(
        'login_failure',
        createSecurityLog({
          type: 'login_failure',
          ip: clientIP,
          userAgent,
          username: cleanUsername,
          details: { reason: 'invalid_password', failedAttempts }
        }),
        clientIP,
        userAgent
      ).run();
      
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401, headers: getSecurityHeaders() }
      );
    }

    // Reset failed attempts on successful login
    const resetRateLimitStmt = await db.prepare('DELETE FROM admin_rate_limit WHERE ip_address = ?');
    await resetRateLimitStmt.bind(clientIP).run();

    // Update last login
    const updatePrepared = await db.prepare('UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?');
    await updatePrepared.bind(user.id).run();

    // Generate session token
    const sessionToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + SECURITY_CONFIG.SESSION_DURATION);
    
    // Store session in database
    const sessionStmt = await db.prepare(`
      INSERT INTO admin_sessions (token, user_id, ip_address, user_agent, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    await sessionStmt.bind(
      sessionToken,
      user.id,
      clientIP,
      userAgent,
      expiresAt.toISOString()
    ).run();
    
    // Log successful login
    const logPrepared = await db.prepare(`
      INSERT INTO admin_logs (action, data, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
    `);
    await logPrepared.bind(
      'login_success',
      createSecurityLog({
        type: 'login_success',
        ip: clientIP,
        userAgent,
        username: user.username,
        details: { session_id: sessionToken.substring(0, 8) + '...' }
      }),
      clientIP,
      userAgent
    ).run();

    const response = NextResponse.json({
      success: true,
      redirect: '/admin',
      user: {
        id: user.id,
        username: user.username,
        last_login: user.last_login
      }
    }, { headers: getSecurityHeaders() });

    // Set secure session cookie
    response.cookies.set('admin_session', sessionToken, getSessionCookieOptions(process.env.NODE_ENV === 'production'));

    return response;

  } catch (error) {
    console.error('Error in admin auth:', error);
    return NextResponse.json(
      { error: 'Authentication failed' },
      { status: 500, headers: getSecurityHeaders() }
    );
  }
}

// GET - Check admin session status
export async function GET(request: NextRequest) {
  try {
    const sessionToken = request.cookies.get('admin_session')?.value;
    
    if (!sessionToken || !isValidSessionToken(sessionToken)) {
      return NextResponse.json(
        { authenticated: false },
        { headers: getSecurityHeaders() }
      );
    }

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { authenticated: false },
        { headers: getSecurityHeaders() }
      );
    }

    // Validate session against database
    const sessionStmt = await db.prepare(`
      SELECT s.*, u.username, u.last_login 
      FROM admin_sessions s 
      JOIN admin_users u ON s.user_id = u.id 
      WHERE s.token = ? AND s.expires_at > datetime('now') AND s.is_active = 1 AND u.is_active = 1
    `);
    const session = await sessionStmt.bind(sessionToken).first() as any;

    if (!session) {
      // Log session validation failure
      const clientIP = getClientIP(request);
      const userAgent = request.headers.get('user-agent') || 'unknown';
      
      const logStmt = await db.prepare(`
        INSERT INTO admin_logs (action, data, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
      `);
      await logStmt.bind(
        'session_expired',
        createSecurityLog({
          type: 'session_expired',
          ip: clientIP,
          userAgent,
          details: { token_prefix: sessionToken.substring(0, 8) + '...' }
        }),
        clientIP,
        userAgent
      ).run();
      
      return NextResponse.json(
        { authenticated: false },
        { headers: getSecurityHeaders() }
      );
    }

    // Update session last activity (extend expiration)
    const newExpiration = new Date(Date.now() + SECURITY_CONFIG.SESSION_DURATION).toISOString();
    const updateStmt = await db.prepare('UPDATE admin_sessions SET expires_at = ? WHERE token = ?');
    await updateStmt.bind(newExpiration, sessionToken).run();

    return NextResponse.json({
      authenticated: true,
      user: {
        id: session.user_id,
        username: session.username,
        last_login: session.last_login
      }
    }, { headers: getSecurityHeaders() });

  } catch (error) {
    console.error('Error checking admin session:', error);
    return NextResponse.json(
      { authenticated: false },
      { headers: getSecurityHeaders() }
    );
  }
}

// DELETE - Admin logout
export async function DELETE(request: NextRequest) {
  try {
    const sessionToken = request.cookies.get('admin_session')?.value;
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';
    const db = getDatabase();
    
    if (db && sessionToken && isValidSessionToken(sessionToken)) {
      // Get session info before deactivating
      const sessionStmt = await db.prepare(`
        SELECT s.user_id, u.username 
        FROM admin_sessions s 
        JOIN admin_users u ON s.user_id = u.id 
        WHERE s.token = ?
      `);
      const session = await sessionStmt.bind(sessionToken).first() as any;
      
      // Deactivate session in database
      const deactivateStmt = await db.prepare('UPDATE admin_sessions SET is_active = 0 WHERE token = ?');
      await deactivateStmt.bind(sessionToken).run();
      
      // Log logout
      const logPrepared = await db.prepare(`
        INSERT INTO admin_logs (action, data, ip_address, user_agent)
        VALUES (?, ?, ?, ?)
      `);
      await logPrepared.bind(
        'logout',
        createSecurityLog({
          type: 'logout',
          ip: clientIP,
          userAgent,
          username: session?.username,
          details: { session_id: sessionToken.substring(0, 8) + '...' }
        }),
        clientIP,
        userAgent
      ).run();
    }

    const response = NextResponse.json(
      { success: true, message: 'Logged out successfully' },
      { headers: getSecurityHeaders() }
    );
    
    // Clear session cookie
    const cookieOptions = getSessionCookieOptions(process.env.NODE_ENV === 'production');
    response.cookies.set('admin_session', '', {
      ...cookieOptions,
      maxAge: 0
    });

    return response;

  } catch (error) {
    console.error('Error in admin logout:', error);
    return NextResponse.json(
      { error: 'Logout failed' },
      { status: 500, headers: getSecurityHeaders() }
    );
  }
}