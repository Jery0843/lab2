import { NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';
import { NewsletterDB } from '@/lib/newsletter-db';

export async function GET() {
  try {
    const db = getDatabase();
    if (!db) {
      return NextResponse.json({ error: 'Database not available' }, { status: 503 });
    }

    // Get members count
    const membersStmt = await db.prepare('SELECT COUNT(*) as count FROM members');
    const membersResult = await membersStmt.first();
    const membersCount = membersResult?.count || 0;

    // Get newsletter subscribers count
    const newsletterDB = new NewsletterDB();
    const subscribers = await newsletterDB.getAllSubscribers();
    const subscribersCount = subscribers.length;

    return NextResponse.json({
      members: membersCount,
      subscribers: subscribersCount
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    return NextResponse.json({ error: 'Failed to fetch stats' }, { status: 500 });
  }
}