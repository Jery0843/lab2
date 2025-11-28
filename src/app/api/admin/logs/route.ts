import { NextResponse, NextRequest } from 'next/server';
import { getDatabase } from '@/lib/db';

interface AdminLog {
  id: number;
  action: string;
  data?: string;
  ip_address?: string;
  user_agent?: string;
  timestamp: string;
}

// Verify session token (simplified for demo - in production you'd validate against a sessions table)
function verifySession(request: NextRequest): boolean {
  const sessionToken = request.cookies.get('admin_session')?.value;
  return Boolean(sessionToken && sessionToken.length === 64);
}

// GET - Get admin audit logs
export async function GET(request: NextRequest) {
  try {
    // Check authentication
    if (!verifySession(request)) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(request.url);
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const action = searchParams.get('action');

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    let query = 'SELECT * FROM admin_logs';
    let params: any[] = [];

    // Filter by action if provided
    if (action) {
      query += ' WHERE action = ?';
      params.push(action);
    }

    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const prepared = await db.prepare(query);
    const logs = await prepared.bind(...params).all() as AdminLog[];

    // Get total count for pagination
    let countQuery = 'SELECT COUNT(*) as total FROM admin_logs';
    let countParams: any[] = [];
    
    if (action) {
      countQuery += ' WHERE action = ?';
      countParams.push(action);
    }

    const countPrepared = await db.prepare(countQuery);
    const countResult = await countPrepared.bind(...countParams).first() as { total: number };

    // Parse JSON data for better readability
    const processedLogs = logs.map(log => ({
      ...log,
      data: log.data ? JSON.parse(log.data) : null
    }));

    return NextResponse.json({
      logs: processedLogs,
      pagination: {
        total: countResult.total,
        limit,
        offset,
        hasMore: offset + limit < countResult.total
      }
    });

  } catch (error) {
    console.error('Error fetching admin logs:', error);
    return NextResponse.json(
      { error: 'Failed to fetch admin logs' },
      { status: 500 }
    );
  }
}

// DELETE - Clear old logs (optional maintenance endpoint)
export async function DELETE(request: NextRequest) {
  try {
    // Check authentication
    if (!verifySession(request)) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(request.url);
    const daysOld = parseInt(searchParams.get('days') || '30');

    const db = getDatabase();
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available' },
        { status: 503 }
      );
    }

    // Delete logs older than specified days
    const prepared = await db.prepare('DELETE FROM admin_logs WHERE timestamp < datetime("now", "-" || ? || " days")');
    const result = await prepared.bind(daysOld).run();

    // Log the cleanup action
    const logPrepared = await db.prepare(`
      INSERT INTO admin_logs (action, data, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
    `);
    await logPrepared.bind(
      'admin_logs_cleanup',
      JSON.stringify({ daysOld, deletedCount: result.changes }),
      request.headers.get('x-forwarded-for') || 'unknown',
      request.headers.get('user-agent') || 'unknown'
    ).run();

    return NextResponse.json({
      success: true,
      message: `Deleted ${result.changes} log entries older than ${daysOld} days`
    });

  } catch (error) {
    console.error('Error cleaning admin logs:', error);
    return NextResponse.json(
      { error: 'Failed to clean admin logs' },
      { status: 500 }
    );
  }
}
