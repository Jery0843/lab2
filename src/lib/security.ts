import crypto from 'crypto';
import { NextRequest } from 'next/server';

// Security configuration
export const SECURITY_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  SESSION_DURATION: 24 * 60 * 60 * 1000, // 24 hours
  CLEANUP_INTERVAL: 60 * 60 * 1000, // 1 hour
  RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 100,
};

// Generate cryptographically secure random token
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

// Hash password with salt using PBKDF2
export function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

// Generate random salt
export function generateSalt(): string {
  return crypto.randomBytes(32).toString('hex');
}

// Verify password using timing-safe comparison
export function verifyPassword(password: string, hash: string, salt: string): boolean {
  const hashToCompare = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(hashToCompare, 'hex'));
}

// Extract client IP address from request
export function getClientIP(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for');
  const realIP = request.headers.get('x-real-ip');
  const remoteAddr = request.headers.get('x-vercel-forwarded-for');
  
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  
  return realIP || remoteAddr || 'unknown';
}

// Validate session token format
export function isValidSessionToken(token: string): boolean {
  return typeof token === 'string' && token.length === 64 && /^[a-f0-9]+$/.test(token);
}

// Security headers for admin responses
export function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };
}

// Sanitize user input
export function sanitizeInput(input: string): string {
  return input.trim().replace(/[<>\"'&]/g, '');
}

// Validate admin username format
export function isValidUsername(username: string): boolean {
  return /^[a-zA-Z0-9_-]{3,20}$/.test(username);
}

// Validate password strength
export function isStrongPassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// Generate secure session cookie options
export function getSessionCookieOptions(isProduction: boolean) {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict' as const,
    maxAge: SECURITY_CONFIG.SESSION_DURATION,
    path: '/',
  };
}

// Log security events
export interface SecurityEvent {
  type: 'login_attempt' | 'login_success' | 'login_failure' | 'logout' | 'session_expired' | 'rate_limit_exceeded';
  ip: string;
  userAgent: string;
  username?: string;
  details?: Record<string, any>;
}

export function createSecurityLog(event: SecurityEvent): string {
  return JSON.stringify({
    ...event,
    timestamp: new Date().toISOString(),
    severity: getSeverityLevel(event.type),
  });
}

function getSeverityLevel(eventType: SecurityEvent['type']): 'low' | 'medium' | 'high' {
  switch (eventType) {
    case 'login_success':
    case 'logout':
      return 'low';
    case 'login_attempt':
    case 'session_expired':
      return 'medium';
    case 'login_failure':
    case 'rate_limit_exceeded':
      return 'high';
    default:
      return 'medium';
  }
}