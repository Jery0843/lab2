import { NextResponse, NextRequest } from 'next/server';
import { getDatabase } from '@/lib/db';
import crypto from 'crypto';

// Get location data from IP
async function getLocationFromIP(ip: string) {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}`);
    const data = await response.json();
    
    if (data.status === 'success') {
      return {
        country: data.country || 'Unknown',
        region: data.regionName || 'Unknown',
        city: data.city || 'Unknown'
      };
    }
  } catch (error) {
    console.error('Error getting location:', error);
  }
  
  return {
    country: 'Unknown',
    region: 'Unknown', 
    city: 'Unknown'
  };
}

export async function POST(request: NextRequest) {
  try {
    const { email, otp, machineId, name, verificationToken } = await request.json();
    const clientIP = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    if (!email || !otp || !machineId) {
      return NextResponse.json(
        { error: 'Email, OTP, and machine ID are required' },
        { status: 400 }
      );
    }
    
    // Validate verification token if provided
    if (verificationToken) {
      try {
        const decoded = Buffer.from(verificationToken, 'base64').toString();
        const [tokenMachineId] = decoded.split(':');
        
        if (tokenMachineId !== machineId) {
          return NextResponse.json(
            { error: 'Invalid verification token' },
            { status: 401 }
          );
        }
      } catch (error) {
        return NextResponse.json(
          { error: 'Invalid verification token format' },
          { status: 401 }
        );
      }
    }

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Hash the provided OTP to compare with stored hash
    const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');

    // Verify OTP
    const otpStmt = await db.prepare(`
      SELECT * FROM otp_verification 
      WHERE email = ? AND otp_code = ? AND expires_at > datetime('now') AND verified = 0
      ORDER BY created_at DESC LIMIT 1
    `);
    const otpRecord = await otpStmt.bind(email, hashedOtp).first();

    if (!otpRecord) {
      return NextResponse.json(
        { error: 'Invalid or expired OTP' },
        { status: 401 }
      );
    }

    // Mark OTP as verified
    const markVerifiedStmt = await db.prepare('UPDATE otp_verification SET verified = 1 WHERE id = ?');
    await markVerifiedStmt.bind(otpRecord.id).run();

    // Get member details - check if active
    const memberStmt = await db.prepare('SELECT * FROM members WHERE email = ? AND status = "active"');
    const member = await memberStmt.bind(email).first();

    if (!member) {
      return NextResponse.json(
        { error: 'Access denied - inactive membership' },
        { status: 403 }
      );
    }

    // Get location data
    const location = await getLocationFromIP(clientIP);

    // Update member with location if not set
    if (member && (!member.country || !member.region || !member.city)) {
      const updateLocationStmt = await db.prepare(`
        UPDATE members 
        SET country = COALESCE(country, ?), region = COALESCE(region, ?), city = COALESCE(city, ?) 
        WHERE email = ?
      `);
      await updateLocationStmt.bind(location.country, location.region, location.city, email).run();
    }

    // Log writeup access
    const logAccessStmt = await db.prepare(`
      INSERT INTO writeup_access_logs (machine_id, email, name, ip_address, country, region, city, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await logAccessStmt.bind(
      machineId,
      email,
      name || member?.name || 'Unknown',
      clientIP,
      location.country,
      location.region,
      location.city,
      userAgent
    ).run();

    // Try to get HTB machine writeup first
    const machineStmt = await db.prepare('SELECT writeup FROM htb_machines WHERE id = ?');
    const machine = await machineStmt.bind(machineId).first();

    if (machine && machine.writeup) {
      return NextResponse.json({
        success: true,
        writeup: machine.writeup
      });
    }

    // If not found in HTB machines, try CTF writeups
    const ctfStmt = await db.prepare('SELECT writeup FROM ctf_writeups WHERE id = ?');
    const ctfWriteup = await ctfStmt.bind(machineId).first();

    if (ctfWriteup && ctfWriteup.writeup) {
      return NextResponse.json({
        success: true,
        writeup: ctfWriteup.writeup
      });
    }

    return NextResponse.json({
      success: true,
      message: 'OTP verified successfully'
    });

  } catch (error) {
    console.error('Error in OTP verification:', error);
    return NextResponse.json(
      { error: 'Verification failed' },
      { status: 500 }
    );
  }
}
