import { NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';

// POST - Cleanup expired sessions (can be called by cron job)
export async function POST() {
  try {
    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // First check what sessions would be deleted
    const checkStmt = await db.prepare(`
      SELECT * FROM admin_sessions 
      WHERE expires_at < datetime('now') OR is_active = 0
    `);
    const expiredSessions = await checkStmt.all();
    console.log('Sessions to be deleted:', expiredSessions);
    
    // Delete expired sessions
    const cleanupStmt = await db.prepare(`
      DELETE FROM admin_sessions 
      WHERE expires_at < datetime('now') OR is_active = 0
    `);
    const result = await cleanupStmt.run();
    console.log('Cleanup result:', result);

    // Log cleanup action
    const logStmt = await db.prepare(`
      INSERT INTO admin_logs (action, data, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
    `);
    await logStmt.bind(
      'session_cleanup',
      JSON.stringify({ 
        sessions_removed: result.changes,
        expired_found: expiredSessions.results?.length || 0
      }),
      'system',
      'cleanup-job'
    ).run();

    return NextResponse.json({
      success: true,
      message: `Cleaned up ${result.changes} expired sessions`
    });

  } catch (error) {
    console.error('Error cleaning up sessions:', error);
    return NextResponse.json(
      { error: 'Cleanup failed' },
      { status: 500 }
    );
  }
}

// GET - Get session statistics
export async function GET() {
  try {
    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Get session statistics
    const statsStmt = await db.prepare(`
      SELECT 
        COUNT(*) as total_sessions,
        COUNT(CASE WHEN expires_at > datetime('now') AND is_active = 1 THEN 1 END) as active_sessions,
        COUNT(CASE WHEN expires_at <= datetime('now') OR is_active = 0 THEN 1 END) as expired_sessions
      FROM admin_sessions
    `);
    const stats = await statsStmt.first() as any;

    return NextResponse.json({
      success: true,
      stats: {
        total: stats.total_sessions,
        active: stats.active_sessions,
        expired: stats.expired_sessions
      }
    });

  } catch (error) {
    console.error('Error getting session stats:', error);
    return NextResponse.json(
      { error: 'Failed to get session statistics' },
      { status: 500 }
    );
  }
}