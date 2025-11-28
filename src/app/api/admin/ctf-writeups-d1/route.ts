import { NextResponse, NextRequest } from 'next/server';
import { CTFWriteupsDB, getDatabase } from '@/lib/db';
import { emailService } from '@/lib/email-service';

interface CTFWriteup {
  id: string;
  title: string;
  slug: string;
  ctf_name: string;
  category: string;
  difficulty: string;
  points?: number;
  status: string;
  is_active?: number;
  password?: string | null;
  date_completed?: string | null;
  tags: string;
  writeup?: string | null;
  summary?: string | null;
  flag?: string | null;
  created_at?: string;
  updated_at?: string;
}

interface CTFWriteupInput {
  id?: string;
  title: string;
  slug?: string;
  ctfName: string;
  category: string;
  difficulty: string;
  points?: number;
  status: string;
  isActive?: boolean;
  password?: string | null;
  dateCompleted?: string | null;
  tags: string[];
  writeup?: string | null;
  summary?: string | null;
  flag?: string | null;
}

// Helper function to convert database format to API format
function dbToApiFormat(dbWriteup: any): CTFWriteupInput {
  return {
    id: dbWriteup.id,
    title: dbWriteup.title,
    slug: dbWriteup.slug,
    ctfName: dbWriteup.ctf_name,
    category: dbWriteup.category,
    difficulty: dbWriteup.difficulty,
    points: dbWriteup.points || 0,
    status: dbWriteup.status,
    isActive: Boolean(dbWriteup.is_active),
    password: dbWriteup.password,
    dateCompleted: dbWriteup.date_completed,
    tags: dbWriteup.tags ? (() => {
      try {
        // Decode HTML entities first
        const decodedTags = dbWriteup.tags.replace(/&quot;/g, '"').replace(/&#39;/g, "'");
        return JSON.parse(decodedTags);
      } catch (e) {
        console.warn('Failed to parse tags JSON:', dbWriteup.tags);
        return [];
      }
    })() : [],
    writeup: dbWriteup.writeup,
    summary: dbWriteup.summary,
    flag: dbWriteup.flag
  };
}

// Helper function to convert API format to database format
function apiToDbFormat(apiWriteup: CTFWriteupInput): CTFWriteup {
  const slug = apiWriteup.slug || apiWriteup.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
  return {
    id: apiWriteup.id || `${apiWriteup.ctfName.toLowerCase().replace(/\s+/g, '-')}-${slug}`,
    title: apiWriteup.title,
    slug: slug,
    ctf_name: apiWriteup.ctfName,
    category: apiWriteup.category,
    difficulty: apiWriteup.difficulty,
    points: apiWriteup.points || 0,
    status: apiWriteup.status,
    is_active: apiWriteup.isActive ? 1 : 0,
    password: apiWriteup.password || null,
    date_completed: apiWriteup.dateCompleted || null,
    tags: JSON.stringify(apiWriteup.tags || []),
    writeup: apiWriteup.writeup || null,
    summary: apiWriteup.summary || null,
    flag: apiWriteup.flag || null
  };
}

// Session-based authentication helper
async function checkAuth(request: NextRequest): Promise<boolean> {
  try {
    const sessionToken = request.cookies.get('admin_session')?.value;
    return Boolean(sessionToken && sessionToken.length === 64);
  } catch (error) {
    console.error('Error checking admin auth:', error);
    return false;
  }
}

// GET - Fetch all CTF writeups from D1 database
export async function GET(request: NextRequest) {
  try {
    console.log('🔍 Fetching CTF writeups from database...');
    const writeupsDB = new CTFWriteupsDB();

    const dbWriteups = await writeupsDB.getAllWriteups();

    console.log('📊 Raw database writeups:', dbWriteups.length, 'found');

    const isAdmin = await checkAuth(request);
    let writeups = dbWriteups.map(dbToApiFormat);
    
    // If not admin, hide flags, passwords and full writeups for incomplete/active challenges
    if (!isAdmin) {
      writeups = writeups.map(w => ({
        ...w,
        flag: undefined,
        password: undefined,
        writeup: (w.status === 'Completed' && !w.isActive) ? w.writeup : null,
      }));
    }

    console.log('✅ Returning', writeups.length, 'writeups');
    return NextResponse.json(writeups);
  } catch (error) {
    console.error('❌ Error fetching CTF writeups from D1:', error);

    return NextResponse.json(
      { error: 'Failed to fetch writeups from database' },
      { status: 500 }
    );
  }
}

// POST - Add new CTF writeup to D1 database
export async function POST(request: NextRequest) {
  try {
    // Check authentication
    if (!(await checkAuth(request))) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const writeupData: CTFWriteupInput = await request.json();

    // Validate required fields
    if (!writeupData.title || !writeupData.ctfName || !writeupData.category || !writeupData.difficulty || !writeupData.status) {
      return NextResponse.json(
        { error: 'Missing required fields: title, ctfName, category, difficulty, status' },
        { status: 400 }
      );
    }

    const writeupsDB = new CTFWriteupsDB();
    // Default isActive to false if not provided
    const dbWriteup = apiToDbFormat({ ...writeupData, isActive: writeupData.isActive ?? false });

    // Check if writeup already exists
    const existing = await writeupsDB.getWriteup(dbWriteup.id);

    if (existing) {
      return NextResponse.json(
        { error: 'Writeup with this ID already exists' },
        { status: 409 }
      );
    }

    // Create new writeup
    const created = await writeupsDB.createWriteup(dbWriteup);

    if (!created) {
      return NextResponse.json(
        { error: 'Failed to create writeup' },
        { status: 500 }
      );
    }

    // Send notification email for completed writeups (async, don't wait)
    if (created.status === 'Completed' && created.writeup) {
      emailService.sendNewWriteupNotification(
        created.title,
        created.ctf_name,
        created.category,
        created.difficulty
      ).catch(error => {
        console.error('Failed to send writeup notification:', error);
      });
    }

    const isAdmin = await checkAuth(request);
    const safeCreated = dbToApiFormat(created);
    if (!isAdmin) {
      safeCreated.flag = undefined;
      safeCreated.password = undefined;
    }
    
    return NextResponse.json({
      message: 'Writeup created successfully',
      writeup: safeCreated
    });

  } catch (error) {
    console.error('Error creating CTF writeup:', error);
    return NextResponse.json(
      { error: 'Failed to create writeup' },
      { status: 500 }
    );
  }
}

// PUT - Update existing CTF writeup in D1 database
export async function PUT(request: NextRequest) {
  try {
    console.log('🔄 PUT request received for writeup update');

    // Check authentication
    if (!(await checkAuth(request))) {
      console.log('❌ Authentication failed');
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const writeupData: CTFWriteupInput = await request.json();
    console.log('📝 Writeup data received for update:', writeupData);

    // Validate required fields
    if (!writeupData.id || !writeupData.title || !writeupData.ctfName || !writeupData.category || !writeupData.difficulty || !writeupData.status) {
      return NextResponse.json(
        { error: 'Missing required fields: id, title, ctfName, category, difficulty, status' },
        { status: 400 }
      );
    }

    const writeupsDB = new CTFWriteupsDB();
    const dbWriteup = apiToDbFormat(writeupData);

    // Check if writeup exists
    const existing = await writeupsDB.getWriteup(writeupData.id as string);

    if (!existing) {
      return NextResponse.json(
        { error: 'Writeup not found' },
        { status: 404 }
      );
    }

    // Update writeup
    const updated = await writeupsDB.updateWriteup(dbWriteup.id, dbWriteup);

    if (!updated) {
      return NextResponse.json(
        { error: 'Failed to update writeup' },
        { status: 500 }
      );
    }

    // Send notification if writeup was just completed and has content (async, don't wait)
    if (updated.status === 'Completed' && updated.writeup && 
        existing.status !== 'Completed') {
      emailService.sendNewWriteupNotification(
        updated.title,
        updated.ctf_name,
        updated.category,
        updated.difficulty
      ).catch(error => {
        console.error('Failed to send writeup notification:', error);
      });
    }

    const isAdmin = await checkAuth(request);
    const safeUpdated = dbToApiFormat(updated);
    if (!isAdmin) {
      safeUpdated.flag = undefined;
      safeUpdated.password = undefined;
    }
    
    return NextResponse.json({
      message: 'Writeup updated successfully',
      writeup: safeUpdated
    });

  } catch (error) {
    console.error('Error updating CTF writeup:', error);
    return NextResponse.json(
      { error: 'Failed to update writeup' },
      { status: 500 }
    );
  }
}

// DELETE - Remove CTF writeup from D1 database
export async function DELETE(request: NextRequest) {
  try {
    // Check authentication
    if (!(await checkAuth(request))) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(request.url);
    const writeupId = searchParams.get('id');

    if (!writeupId) {
      return NextResponse.json(
        { error: 'Writeup ID is required' },
        { status: 400 }
      );
    }

    const writeupsDB = new CTFWriteupsDB();

    // Check if writeup exists
    const existing = await writeupsDB.getWriteup(writeupId);

    if (!existing) {
      return NextResponse.json(
        { error: 'Writeup not found' },
        { status: 404 }
      );
    }

    // Delete writeup
    const success = await writeupsDB.deleteWriteup(writeupId);

    if (!success) {
      return NextResponse.json(
        { error: 'Failed to delete writeup' },
        { status: 500 }
      );
    }

    return NextResponse.json({
      message: 'Writeup deleted successfully',
      writeup: dbToApiFormat(existing)
    });

  } catch (error) {
    console.error('Error deleting CTF writeup:', error);
    return NextResponse.json(
      { error: 'Failed to delete writeup' },
      { status: 500 }
    );
  }
}
