import { NextResponse, NextRequest } from 'next/server';
import { getDatabase } from '@/lib/db';
import crypto from 'crypto';

// Generate cryptographically secure 6-digit OTP
function generateOTP(): string {
  // Use crypto.randomInt for cryptographically secure random numbers
  return crypto.randomInt(100000, 999999).toString();
}

// Send OTP via Mailgun
async function sendOTP(email: string, otp: string): Promise<boolean> {
  try {
    const mailgunApiKey = process.env.MAILGUN_API_KEY;
    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    
    if (!mailgunApiKey || !mailgunDomain) {
      console.error('Mailgun credentials not configured');
      return false;
    }

    const response = await fetch(`https://api.mailgun.net/v3/${mailgunDomain}/messages`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${Buffer.from(`api:${mailgunApiKey}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        from: `0xJerry's Lab <noreply@${mailgunDomain}>`,
        to: email,
        subject: 'Your OTP for Writeup Access',
        text: `Your OTP code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nBest regards,\n0xJerry's Lab`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #00ff41;">0xJerry's Lab - OTP Verification</h2>
            <p>Your OTP code is:</p>
            <div style="background: #f0f0f0; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; margin: 20px 0;">
              ${otp}
            </div>
            <p>This code will expire in 10 minutes.</p>
            <p>Best regards,<br>0xJerry's Lab</p>
          </div>
        `
      })
    });

    return response.ok;
  } catch (error) {
    console.error('Error sending OTP:', error);
    return false;
  }
}

export async function POST(request: NextRequest) {
  try {
    const { email } = await request.json();
    const clientIP = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';

    if (!email) {
      return NextResponse.json(
        { error: 'Email is required' },
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

    // Check if email exists in members table
    const memberStmt = await db.prepare('SELECT * FROM members WHERE email = ?');
    const member = await memberStmt.bind(email).first();

    if (!member) {
      return NextResponse.json(
        { error: 'Email not found in members database. Please contact support.' },
        { status: 404 }
      );
    }

    // Update member IP if not set
    if (!member.ip_address) {
      const updateIpStmt = await db.prepare('UPDATE members SET ip_address = ? WHERE email = ?');
      await updateIpStmt.bind(clientIP, email).run();
    }

    // Check for recent OTP requests (rate limiting)
    const recentOtpStmt = await db.prepare(`
      SELECT COUNT(*) as count FROM otp_verification 
      WHERE email = ? AND created_at > datetime('now', '-2 minutes')
    `);
    const recentOtp = await recentOtpStmt.bind(email).first() as { count: number };
    
    if (recentOtp.count > 0) {
      return NextResponse.json(
        { error: 'Please wait 2 minutes before requesting another OTP' },
        { status: 429 }
      );
    }

    // Generate cryptographically secure OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 minutes

    // Hash OTP before storing (additional security layer)
    const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');

    // Store hashed OTP in database
    const otpStmt = await db.prepare(`
      INSERT INTO otp_verification (email, otp_code, expires_at)
      VALUES (?, ?, ?)
    `);
    await otpStmt.bind(email, hashedOtp, expiresAt).run();

    // Send OTP via email
    const emailSent = await sendOTP(email, otp);

    if (!emailSent) {
      return NextResponse.json(
        { error: 'Failed to send OTP. Please try again.' },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'OTP sent to your email address'
    });

  } catch (error) {
    console.error('Error in email verification:', error);
    return NextResponse.json(
      { error: 'Verification failed' },
      { status: 500 }
    );
  }
}