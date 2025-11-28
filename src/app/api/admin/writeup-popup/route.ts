import { NextResponse, NextRequest } from 'next/server';
import { getDatabase } from '@/lib/db';

interface WriteupPopup {
  id: string;
  title: string;
  imageUrl: string;
  link: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

async function checkAuth(request: NextRequest): Promise<boolean> {
  try {
    const sessionToken = request.cookies.get('admin_session')?.value;
    return Boolean(sessionToken && sessionToken.length === 64);
  } catch (error) {
    console.error('Error checking admin auth:', error);
    return false;
  }
}

export async function GET() {
  try {
    const db = getDatabase();
    if (!db) {
      return NextResponse.json({ error: 'Database not available' }, { status: 503 });
    }

    const stmt = await db.prepare('SELECT * FROM writeup_popup WHERE id = 1');
    const result = await stmt.first();
    
    if (!result) {
      return NextResponse.json({
        id: '1',
        title: '',
        imageUrl: '',
        link: '',
        isActive: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    }

    return NextResponse.json({
      id: result.id,
      title: result.title,
      imageUrl: result.image_url,
      link: result.link,
      isActive: Boolean(result.is_active),
      createdAt: result.created_at,
      updatedAt: result.updated_at
    });
  } catch (error) {
    console.error('Error fetching writeup popup:', error);
    return NextResponse.json({ error: 'Failed to fetch popup data' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const { title, imageUrl, link, isActive } = await request.json();
    console.log('Received data:', { title, imageUrl, link, isActive });

    if (!title || !link) {
      return NextResponse.json({ error: 'Title and link are required' }, { status: 400 });
    }

    const db = getDatabase();
    if (!db) {
      console.log('Database not available');
      return NextResponse.json({ error: 'Database not available' }, { status: 503 });
    }

    console.log('Database connected, attempting insert...');
    
    // Try a simpler approach first
    const stmt = await db.prepare(`
      INSERT OR REPLACE INTO writeup_popup 
      (id, title, image_url, link, is_active)
      VALUES (1, ?, ?, ?, ?)
    `);
    const result = await stmt.bind(title, imageUrl || '', link, isActive ? 1 : 0).run();

    console.log('Insert result:', result);

    if (result.success) {
      const selectStmt = await db.prepare('SELECT * FROM writeup_popup WHERE id = 1');
      const updated = await selectStmt.first();
      console.log('Retrieved updated record:', updated);
      
      return NextResponse.json({
        id: updated.id,
        title: updated.title,
        imageUrl: updated.image_url,
        link: updated.link,
        isActive: Boolean(updated.is_active),
        createdAt: updated.created_at,
        updatedAt: updated.updated_at
      });
    }

    return NextResponse.json({ error: 'Failed to save popup' }, { status: 500 });
  } catch (error) {
    console.error('Detailed error:', error);
    return NextResponse.json({ error: `Database error: ${error instanceof Error ? error.message : 'Unknown error'}` }, { status: 500 });
  }
}