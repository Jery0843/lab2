import { NextResponse, NextRequest } from 'next/server';
import { HTBStatsDB, AdminLogDB } from '@/lib/db';

interface HTBStats {
  machinesPwned?: number;
  machines_pwned?: number;
  globalRanking?: number;
  global_ranking?: number;
  finalScore?: number;
  final_score?: number;
  htbRank?: string;
  htb_rank?: string;
  lastUpdated?: string;
  last_updated?: string;
}

// GET - Fetch HTB stats from D1 database
export async function GET() {
  try {
    console.log('🔍 Fetching HTB stats from database...');
    const statsDB = new HTBStatsDB();
    const stats = await statsDB.getStats();
    
    console.log('📊 Raw database stats:', stats);
    
    if (!stats) {
      console.log('⚠️ No stats found in database, returning null');
      return NextResponse.json(
        { error: 'No stats found in database' }, 
        { status: 404 }
      );
    }
    
    // Convert database format to API format
    const apiStats = {
      machinesPwned: stats.machines_pwned,
      globalRanking: stats.global_ranking,
      finalScore: stats.final_score,
      htbRank: stats.htb_rank,
      lastUpdated: stats.last_updated,
      id: stats.id,
      createdAt: stats.created_at
    };
    
    console.log('✅ Returning API stats:', apiStats);
    return NextResponse.json(apiStats);
  } catch (error) {
    console.error('❌ Error fetching HTB stats from D1:', error);
    
    return NextResponse.json(
      { error: 'Failed to fetch stats from database' }, 
      { status: 500 }
    );
  }
}

// Helper function to check admin session
async function checkAdminAuth(request: NextRequest): Promise<boolean> {
  try {
    const sessionToken = request.cookies.get('admin_session')?.value;
    // In a production app, you'd validate the session token against a sessions table
    // For now, we'll check if the cookie exists and is valid format
    return Boolean(sessionToken && sessionToken.length === 64);
  } catch (error) {
    console.error('Error checking admin auth:', error);
    return false;
  }
}

// POST - Update HTB stats in D1 database
export async function POST(request: NextRequest) {
  try {
    // Check authentication
    if (!(await checkAdminAuth(request))) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Handle empty request body
    let newStats: any = {};
    try {
      const body = await request.text();
      if (body.trim()) {
        newStats = JSON.parse(body);
      }
    } catch (parseError) {
      console.log('No JSON body provided, using default stats update');
    }
    
    console.log('Received stats update:', newStats);
    
    // Prepare stats for database with defaults
    const dbStats = {
      machines_pwned: newStats.machines_pwned ?? newStats.machinesPwned ?? 0,
      global_ranking: newStats.global_ranking ?? newStats.globalRanking ?? 0,
      final_score: newStats.final_score ?? newStats.finalScore ?? 0,
      htb_rank: newStats.htb_rank || newStats.htbRank || 'Noob',
      last_updated: new Date().toISOString()
    };
    
    console.log('Database update payload:', dbStats);
    
    // Update in database
    const statsDB = new HTBStatsDB();
    const updatedStats = await statsDB.updateStats(dbStats);
    
    if (!updatedStats) {
      return NextResponse.json(
        { error: 'Failed to update stats in database' }, 
        { status: 500 }
      );
    }
    
    // Log admin action
    try {
      const adminLogDB = new AdminLogDB();
      await adminLogDB.log({
        action: 'UPDATE_HTB_STATS',
        data: JSON.stringify(dbStats),
        ip_address: request.headers.get('x-forwarded-for') || 
                   request.headers.get('x-real-ip') || 
                   'unknown',
        user_agent: request.headers.get('user-agent') || 'unknown'
      });
    } catch (logError) {
      console.error('Error logging admin action:', logError);
      // Don't fail the request if logging fails
    }
    
    // Return updated stats in API format
    const apiStats = {
      machinesPwned: updatedStats.machines_pwned,
      globalRanking: updatedStats.global_ranking,
      finalScore: updatedStats.final_score,
      htbRank: updatedStats.htb_rank,
      lastUpdated: updatedStats.last_updated
    };
    
    return NextResponse.json(apiStats);
  } catch (error) {
    console.error('Error updating HTB stats in D1:', error);
    return NextResponse.json(
      { error: 'Failed to update stats' }, 
      { status: 500 }
    );
  }
}

// PUT - Update HTB stats in D1 database (proper REST method)
export async function PUT(request: NextRequest) {
  try {
    // Check authentication
    if (!(await checkAdminAuth(request))) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    console.log('🔄 PUT request received for HTB stats update');
    const newStats = await request.json();
    console.log('📝 HTB stats data received for update:', newStats);
    
    // Validate input - handle both API and DB field names
    const machinesPwned = newStats.machinesPwned ?? newStats.machines_pwned;
    const globalRanking = newStats.globalRanking ?? newStats.global_ranking;
    const finalScore = newStats.finalScore ?? newStats.final_score;
    const htbRank = newStats.htbRank || newStats.htb_rank;
    
    if (machinesPwned === undefined || globalRanking === undefined || finalScore === undefined || !htbRank) {
      return NextResponse.json(
        { error: 'Missing required fields' }, 
        { status: 400 }
      );
    }
    
    // Prepare stats for database (convert to DB field names)
    const dbStats = {
      machines_pwned: machinesPwned,
      global_ranking: globalRanking,
      final_score: finalScore,
      htb_rank: htbRank,
      last_updated: new Date().toISOString()
    };
    
    console.log('💾 Updating database with stats:', dbStats);
    
    // Update in database
    const statsDB = new HTBStatsDB();
    const updatedStats = await statsDB.updateStats(dbStats);
    
    if (!updatedStats) {
      return NextResponse.json(
        { error: 'Failed to update stats in database' }, 
        { status: 500 }
      );
    }
    
    // Log admin action
    try {
      const adminLogDB = new AdminLogDB();
      await adminLogDB.log({
        action: 'UPDATE_HTB_STATS_PUT',
        data: JSON.stringify(dbStats),
        ip_address: request.headers.get('x-forwarded-for') || 
                   request.headers.get('x-real-ip') || 
                   'unknown',
        user_agent: request.headers.get('user-agent') || 'unknown'
      });
    } catch (logError) {
      console.error('Error logging admin action:', logError);
      // Don't fail the request if logging fails
    }
    
    // Return updated stats in API format
    const apiStats = {
      machinesPwned: updatedStats.machines_pwned,
      globalRanking: updatedStats.global_ranking,
      finalScore: updatedStats.final_score,
      htbRank: updatedStats.htb_rank,
      lastUpdated: updatedStats.last_updated
    };
    
    console.log('✅ Successfully updated HTB stats:', apiStats);
    return NextResponse.json(apiStats);
  } catch (error) {
    console.error('❌ Error updating HTB stats in D1:', error);
    return NextResponse.json(
      { error: 'Failed to update stats' }, 
      { status: 500 }
    );
  }
}

// DELETE - Reset HTB stats to defaults (admin only)
export async function DELETE(request: NextRequest) {
  try {
    // Check authentication
    if (!(await checkAdminAuth(request))) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const defaultStats = {
      machines_pwned: 0,
      global_ranking: 999999,
      final_score: 0,
      htb_rank: 'Noob',
      last_updated: new Date().toISOString()
    };
    
    const statsDB = new HTBStatsDB();
    const resetStats = await statsDB.updateStats(defaultStats);
    
    if (!resetStats) {
      return NextResponse.json(
        { error: 'Failed to reset stats' }, 
        { status: 500 }
      );
    }
    
    // Log admin action
    try {
      const adminLogDB = new AdminLogDB();
      await adminLogDB.log({
        action: 'RESET_HTB_STATS',
        data: JSON.stringify(defaultStats),
        ip_address: request.headers.get('x-forwarded-for') || 'unknown',
        user_agent: request.headers.get('user-agent') || 'unknown'
      });
    } catch (logError) {
      console.error('Error logging admin action:', logError);
    }
    
    return NextResponse.json({
      message: 'HTB stats reset to defaults',
      stats: {
        machinesPwned: defaultStats.machines_pwned,
        globalRanking: defaultStats.global_ranking,
        finalScore: defaultStats.final_score,
        htbRank: defaultStats.htb_rank,
        lastUpdated: defaultStats.last_updated
      }
    });
  } catch (error) {
    console.error('Error resetting HTB stats:', error);
    return NextResponse.json(
      { error: 'Failed to reset stats' }, 
      { status: 500 }
    );
  }
}
