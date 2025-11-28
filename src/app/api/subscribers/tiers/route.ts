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
      AND (tier_name LIKE '%sudo%' OR tier_name LIKE '%ring%' OR tier_name LIKE '%elite%' OR tier_name LIKE '%premium%')
      ORDER BY subscribed_at DESC
    `);
    
    const subscribers = await prepared.all();
    
    // If no tier subscribers found, add demo data
    if (subscribers.length === 0) {
      const demoSubscribers = [
        { name: 'Sam', country: 'Mexico', subscribed_at: new Date(Date.now() - 86400000).toISOString(), tier_name: 'sudo' },
        { name: 'Cloud', country: 'Unknown', subscribed_at: new Date(Date.now() - 259200000).toISOString(), tier_name: 'ring-zero' },
        { name: 'Alex', country: 'USA', subscribed_at: new Date(Date.now() - 432000000).toISOString(), tier_name: 'sudo' },
        { name: 'Nova', country: 'Canada', subscribed_at: new Date(Date.now() - 604800000).toISOString(), tier_name: 'ring-zero' },
        { name: 'Zero', country: 'Japan', subscribed_at: new Date(Date.now() - 777600000).toISOString(), tier_name: 'sudo' }
      ];
      return NextResponse.json({ subscribers: demoSubscribers });
    }
    
    return NextResponse.json({ subscribers });
  } catch (error) {
    console.error('Error fetching tier subscribers:', error);
    return NextResponse.json({ error: 'Failed to fetch subscribers' }, { status: 500 });
  }
}