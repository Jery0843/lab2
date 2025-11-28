import { NextRequest, NextResponse } from 'next/server';
import { THMStatsDB } from '@/lib/db';

// Default THM stats based on the user's example
const defaultTHMStats = {
  thm_rank: '0x4 [Seeker]',
  global_ranking: 381945,
  rooms_completed: 17,
  streak: 5,
  badges: 4,
  total_points: 1200,
  last_updated: new Date().toISOString()
};

// GET: Fetch THM profile stats
export async function GET() {
  try {
    console.log('🔍 Fetching THM stats from database...');
    const statsDB = new THMStatsDB();
    const stats = await statsDB.getStats();
    
    console.log('📊 Raw stats from database:', JSON.stringify(stats, null, 2));
    
    if (!stats) {
      console.log('⚠️ No THM stats in database, returning defaults');
      return NextResponse.json(defaultTHMStats);
    }
    
    console.log('✅ Fetched THM stats from database:', stats);
    return NextResponse.json(stats);
  } catch (error) {
    console.error('❌ Error fetching THM stats:', error);
    
    // Return default stats if database fails
    return NextResponse.json(defaultTHMStats, {
      headers: {
        'X-Fallback': 'true'
      }
    });
  }
}

// POST: Update THM profile stats
export async function POST(request: NextRequest) {
  try {
    // Handle empty request body
    let statsData: any = {};
    try {
      const body = await request.text();
      if (body.trim()) {
        statsData = JSON.parse(body);
      }
    } catch (parseError) {
      console.log('No JSON body provided, using default stats update');
    }
    
    console.log('📝 Received THM stats update:', statsData);
    
    // Validate required fields
    if (!statsData.thm_rank && statsData.rooms_completed === undefined) {
      return NextResponse.json(
        { error: 'At least thm_rank or rooms_completed is required' },
        { status: 400 }
      );
    }
    
    // Prepare update data with current timestamp
    const updateData = {
      thm_rank: statsData.thm_rank || statsData.thmRank || defaultTHMStats.thm_rank,
      global_ranking: statsData.global_ranking || statsData.globalRanking || defaultTHMStats.global_ranking,
      rooms_completed: statsData.rooms_completed !== undefined ? statsData.rooms_completed : 
                      (statsData.roomsCompleted !== undefined ? statsData.roomsCompleted : defaultTHMStats.rooms_completed),
      streak: statsData.streak !== undefined ? statsData.streak : defaultTHMStats.streak,
      badges: statsData.badges !== undefined ? statsData.badges : defaultTHMStats.badges,
      total_points: statsData.total_points || statsData.totalPoints || defaultTHMStats.total_points,
      last_updated: new Date().toISOString()
    };
    
    console.log('💾 Updating THM stats in database:', updateData);
    
    const statsDB = new THMStatsDB();
    const updatedStats = await statsDB.updateStats(updateData);
    
    if (!updatedStats) {
      return NextResponse.json(
        { error: 'Failed to update THM stats in database' },
        { status: 500 }
      );
    }
    
    console.log('✅ Successfully updated THM stats');
    return NextResponse.json(updatedStats);
  } catch (error) {
    console.error('❌ Error updating THM stats:', error);
    return NextResponse.json(
      { error: 'Internal server error', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
