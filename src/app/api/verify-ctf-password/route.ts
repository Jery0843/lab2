import { NextResponse, NextRequest } from 'next/server';
import { CTFWriteupsDB, getDatabase } from '@/lib/db';
import { emailService } from '@/lib/email-service';
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
    const { writeupId, password, email, name, otp, step, verificationToken } = await request.json();

    if (!writeupId || !password) {
      return NextResponse.json(
        { error: 'Writeup ID and password are required' },
        { status: 400 }
      );
    }

    const writeupsDB = new CTFWriteupsDB();
    const writeup = await writeupsDB.getWriteup(writeupId);

    if (!writeup) {
      return NextResponse.json(
        { error: 'Writeup not found' },
        { status: 404 }
      );
    }

    if (!writeup.is_active || !writeup.password) {
      return NextResponse.json(
        { error: 'This writeup does not require password verification' },
        { status: 400 }
      );
    }

    if (password !== writeup.password) {
      return NextResponse.json(
        { error: 'Invalid password' },
        { status: 401 }
      );
    }

    // If only password verification step, return success with a verification token
    if (step === 'password') {
      // Generate a temporary verification token
      const verificationToken = Buffer.from(`${writeupId}:${password}:${Date.now()}`).toString('base64');
      
      return NextResponse.json({
        success: true,
        message: 'Password verified',
        verificationToken
      });
    }

    // For complete step, require email, OTP, and verification token
    if (step === 'complete') {
      if (!email || !otp) {
        return NextResponse.json(
          { error: 'Email and OTP are required for access' },
          { status: 400 }
        );
      }
      
      // Verify the password again for complete step (prevent bypass)
      if (password !== writeup.password) {
        return NextResponse.json(
          { error: 'Invalid password' },
          { status: 401 }
        );
      }
      
      // Validate verification token if provided
      if (verificationToken) {
        try {
          const decoded = Buffer.from(verificationToken, 'base64').toString();
          const [tokenWriteupId, tokenPassword] = decoded.split(':');
          
          if (tokenWriteupId !== writeupId || tokenPassword !== password) {
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

      // Verify OTP directly
      const clientIP = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
      const userAgent = request.headers.get('user-agent') || 'unknown';
      
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
        writeupId,
        email,
        name || member?.name || 'Unknown',
        clientIP,
        location.country,
        location.region,
        location.city,
        userAgent
      ).run();

      // Send email notification about writeup access
      try {
        if (email) {
          emailService.sendWriteupAccessNotification(
            writeup.title,
            writeup.ctf_name,
            email,
            name || 'Anonymous',
            clientIP
          ).catch((err: any) => {
            console.error('Failed to send writeup access notification:', err);
          });
        }
      } catch (error) {
        console.error('Error sending email notification:', error);
      }

      // Return the writeup data for complete step
      return NextResponse.json({
        success: true,
        message: 'Access granted successfully',
        writeup: {
          id: writeup.id,
          title: writeup.title,
          slug: writeup.slug,
          ctfName: writeup.ctf_name,
          ctf_name: writeup.ctf_name,
          category: writeup.category,
          difficulty: writeup.difficulty,
          points: writeup.points,
          status: writeup.status,
          isActive: Boolean(writeup.is_active),
          is_active: writeup.is_active,
          dateCompleted: writeup.date_completed,
          date_completed: writeup.date_completed,
          tags: writeup.tags ? (typeof writeup.tags === 'string' ? JSON.parse(writeup.tags) : writeup.tags) : [],
          writeup: writeup.writeup,
          summary: writeup.summary,
          flag: writeup.flag
        }
      });
    }

    // This should not be reached for valid steps
    return NextResponse.json(
      { error: 'Invalid verification step' },
      { status: 400 }
    );

  } catch (error) {
    console.error('Error verifying CTF password:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
