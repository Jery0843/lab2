import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';

// GET: Check if database tables exist
export async function GET() {
  try {
    const db = getDatabase();
    
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available in this environment' },
        { status: 503 }
      );
    }

    // Check if tables exist
    const tableChecks = [
      'htb_stats',
      'thm_stats', 
      'htb_machines',
      'thm_rooms',
      'cache_data',
      'admin_logs'
    ];

    const results: Record<string, boolean> = {};
    
    for (const table of tableChecks) {
      try {
        // Try to query the table directly to check if it exists
        const prepared = await db.prepare(`SELECT COUNT(*) as count FROM ${table} LIMIT 1`);
        const result = await prepared.first();
        results[table] = true; // If query succeeds, table exists
        console.log(`✅ Table ${table} exists with ${result?.count || 0} rows`);
      } catch (error) {
        // If query fails, table doesn't exist
        results[table] = false;
        console.log(`❌ Table ${table} does not exist:`, error instanceof Error ? error.message : 'Unknown error');
      }
    }

    return NextResponse.json({
      tablesExist: results,
      allTablesExist: Object.values(results).every(exists => exists)
    });
  } catch (error) {
    console.error('Error checking database setup:', error);
    return NextResponse.json(
      { error: 'Failed to check database setup', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}

// POST: Initialize database tables
export async function POST(request: NextRequest) {
  try {
    const db = getDatabase();
    
    if (!db) {
      return NextResponse.json(
        { error: 'Database not available in this environment' },
        { status: 503 }
      );
    }

    const body = await request.json();
    const { force = false } = body;

    // Create tables
    const statements = [
      // HTB Stats table
      `CREATE TABLE IF NOT EXISTS htb_stats (
        id INTEGER PRIMARY KEY,
        machines_pwned INTEGER NOT NULL DEFAULT 0,
        global_ranking INTEGER NOT NULL DEFAULT 0,
        final_score INTEGER NOT NULL DEFAULT 0,
        htb_rank TEXT NOT NULL DEFAULT 'Noob',
        last_updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      
      // THM Stats table
      `CREATE TABLE IF NOT EXISTS thm_stats (
        id INTEGER PRIMARY KEY,
        thm_rank TEXT NOT NULL DEFAULT 'Beginner',
        rooms_completed INTEGER NOT NULL DEFAULT 0,
        streak INTEGER NOT NULL DEFAULT 0,
        badges TEXT,
        last_updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      
      // HTB Machines table
      `CREATE TABLE IF NOT EXISTS htb_machines (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        os TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'In Progress',
        date_completed TEXT,
        tags TEXT,
        writeup TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      
      // THM Rooms table
      `CREATE TABLE IF NOT EXISTS thm_rooms (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        difficulty TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'In Progress',
        date_completed TEXT,
        tags TEXT,
        writeup TEXT,
        url TEXT,
        room_code TEXT,
        points INTEGER DEFAULT 100,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      
      // Cache table
      `CREATE TABLE IF NOT EXISTS cache_data (
        cache_key TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      
      // Admin logs table
      `CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        data TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`
    ];

    // Execute table creation statements
    for (const statement of statements) {
      try {
        await db.prepare(statement).run();
      } catch (error) {
        console.error('Error creating table:', error);
        throw error;
      }
    }

    // Insert initial data if tables are empty
    try {
      // Check if HTB stats exist
      const htbStatsExist = await db.prepare('SELECT COUNT(*) as count FROM htb_stats').first();
      if (!htbStatsExist || htbStatsExist.count === 0) {
        await db.prepare(`
          INSERT INTO htb_stats (id, machines_pwned, global_ranking, final_score, htb_rank, last_updated)
          VALUES (1, 127, 15420, 890, 'Hacker', CURRENT_TIMESTAMP)
        `).run();
      }

      // Check if THM stats exist
      const thmStatsExist = await db.prepare('SELECT COUNT(*) as count FROM thm_stats').first();
      if (!thmStatsExist || thmStatsExist.count === 0) {
        await db.prepare(`
          INSERT INTO thm_stats (id, thm_rank, rooms_completed, streak, badges, last_updated)
          VALUES (1, 'Beginner', 5, 3, ?, CURRENT_TIMESTAMP)
        `).bind(JSON.stringify([
          { name: 'Beginner', icon: '🎯', description: 'Complete first room' },
          { name: 'Explorer', icon: '🗺️', description: 'Complete 5 rooms' },
          { name: 'Persistent', icon: '💪', description: 'Maintain 3-day streak' }
        ])).run();
      }
    } catch (error) {
      console.warn('Warning: Could not insert initial data:', error);
    }

    return NextResponse.json({
      message: 'Database tables created successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error setting up database:', error);
    return NextResponse.json(
      { error: 'Failed to setup database', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
