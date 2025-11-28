import { NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';

export async function GET() {
  try {
    const db = getDatabase();
    if (!db) {
      return NextResponse.json({ error: 'Database not available' }, { status: 500 });
    }

    const prepared = await db.prepare(`
      SELECT name, country, subscribed_at, tier_name 
      FROM members 
      WHERE status = 'active' AND name IS NOT NULL 
      ORDER BY subscribed_at DESC 
      LIMIT 4
    `);
    
    const subscribers = await prepared.all();
    return NextResponse.json({ subscribers });
  } catch (error) {
    console.error('Error fetching latest subscribers:', error);
    return NextResponse.json({ error: 'Failed to fetch subscribers' }, { status: 500 });
  }
}