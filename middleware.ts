import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from './src/lib/db';

// Get client IP with enhanced detection
function getClientIP(request: NextRequest): string {
  return request.headers.get('cf-connecting-ip') ||
         request.headers.get('x-forwarded-for')?.split(',')[0].trim() || 
         request.headers.get('x-real-ip') || 
         request.headers.get('x-vercel-forwarded-for') || 
         'unknown';
}

// Log unauthorized access attempt
async function logUnauthorizedAccess(request: NextRequest, reason: string) {
  try {
    const db = getDatabase();
    if (!db) return;
    
    const clientIP = getClientIP(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';
    const referer = request.headers.get('referer') || null;
    
    // Get location and ISP data from IP using external API
    let country = 'unknown', region = 'unknown', city = 'unknown', isp = 'unknown';
    try {
      if (clientIP !== 'unknown' && clientIP !== 'localhost' && clientIP !== '127.0.0.1') {
        // Try ipapi.co first (better ISP data)
        try {
          const response = await fetch(`https://ipapi.co/${clientIP}/json/`);
          const data = await response.json();
          if (data.country_name) {
            country = data.country_name || 'unknown';
            region = data.region || 'unknown';
            city = data.city || 'unknown';
            isp = data.org || 'unknown';
          }
        } catch (e) {
          // Fallback to ip-api.com
          const response = await fetch(`http://ip-api.com/json/${clientIP}?fields=status,country,regionName,city,isp,org`);
          const data = await response.json();
          if (data.status === 'success') {
            country = data.country || 'unknown';
            region = data.regionName || 'unknown';
            city = data.city || 'unknown';
            isp = data.isp || data.org || 'unknown';
          }
        }
      }
    } catch (error) {
      console.error('Error getting location from IP:', error);
    }
    
    const logStmt = await db.prepare(`
      INSERT INTO admin_unauthorized (ip_address, user_agent, path, reason, country, region, city, isp, referer)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    await logStmt.bind(
      clientIP,
      userAgent,
      request.nextUrl.pathname,
      reason,
      country,
      region,
      city,
      isp,
      referer
    ).run();
  } catch (error) {
    console.error('Failed to log unauthorized access:', error);
  }
}

// Validate admin session token with IP binding
async function validateAdminSession(sessionToken: string, clientIP: string): Promise<boolean> {
  if (!sessionToken || sessionToken.length !== 64) {
    return false;
  }
  
  try {
    const db = getDatabase();
    if (!db) return false;
    
    // Check if session exists, is valid, and matches IP
    const stmt = await db.prepare('SELECT * FROM admin_sessions WHERE token = ? AND ip_address = ? AND expires_at > datetime("now") AND is_active = 1');
    const session = await stmt.bind(sessionToken, clientIP).first();
    
    return !!session;
  } catch (error) {
    console.error('Session validation error:', error);
    return false;
  }
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // Protect admin routes (except unauthorized page)
  if (pathname.startsWith('/admin') && !pathname.includes('/admin/unauthorized')) {
    const sessionToken = request.cookies.get('admin_session')?.value;
    
    if (!sessionToken) {
      await logUnauthorizedAccess(request, 'no_session_token');
      return NextResponse.redirect(new URL('/admin/unauthorized', request.url));
    }
    
    const clientIP = getClientIP(request);
    console.log('🔍 Admin access attempt:', { sessionToken: sessionToken?.substring(0, 8) + '...', clientIP, pathname });
    
    const isValid = await validateAdminSession(sessionToken, clientIP);
    console.log('🔐 Session validation result:', { isValid, clientIP });
    
    if (!isValid) {
      console.log('❌ Access denied - IP mismatch or invalid session');
      await logUnauthorizedAccess(request, 'invalid_session_token');
      const response = NextResponse.redirect(new URL('/admin/unauthorized', request.url));
      response.cookies.delete('admin_session');
      return response;
    }
    
    console.log('✅ Access granted for IP:', clientIP);
  }
  
  // Protect admin API routes (except auth and setup)
  if (pathname.startsWith('/api/admin/') && 
      !pathname.includes('/api/admin/auth') && 
      !pathname.includes('/api/admin/setup')) {
    
    const sessionToken = request.cookies.get('admin_session')?.value;
    
    if (!sessionToken) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const clientIP = getClientIP(request);
    
    const isValid = await validateAdminSession(sessionToken, clientIP);
    if (!isValid) {
      const response = NextResponse.json({ error: 'Session expired' }, { status: 401 });
      response.cookies.delete('admin_session');
      return response;
    }
  }
  
  // Add CORS headers for API routes
  if (pathname.startsWith('/api/')) {
    const response = NextResponse.next();
    
    response.headers.set('Access-Control-Allow-Origin', '*');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-admin-password');
    
    if (request.method === 'OPTIONS') {
      return new NextResponse(null, { status: 200, headers: response.headers });
    }
    
    return response;
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/admin/:path*',
    '/api/:path*',
  ],
};
