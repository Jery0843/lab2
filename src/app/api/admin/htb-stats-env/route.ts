import { NextResponse, NextRequest } from 'next/server';

interface HTBStats {
  machinesPwned: number;
  globalRanking: number;
  finalScore: number;
  htbRank: string;
  lastUpdated: string;
}

// Default stats - can be overridden by environment variables
const getDefaultStats = (): HTBStats => ({
  machinesPwned: parseInt(process.env.HTB_MACHINES_PWNED || '127'),
  globalRanking: parseInt(process.env.HTB_GLOBAL_RANKING || '15420'),
  finalScore: parseInt(process.env.HTB_FINAL_SCORE || '890'),
  htbRank: process.env.HTB_RANK || 'Hacker',
  lastUpdated: new Date().toISOString()
});

// In-memory storage for runtime updates (resets on server restart)
let runtimeStats: HTBStats | null = null;

export async function GET() {
  try {
    // Return runtime stats if available, otherwise default from env vars
    const stats = runtimeStats || getDefaultStats();
    return NextResponse.json(stats);
  } catch (error) {
    console.error('Error getting HTB stats:', error);
    return NextResponse.json(getDefaultStats());
  }
}

export async function POST(request: NextRequest) {
  try {
    // Check for admin authentication
    const adminAuth = request.headers.get('x-admin-auth');
    if (adminAuth !== process.env.ADMIN_SECRET_KEY) {
      return NextResponse.json(
        { error: 'Unauthorized' }, 
        { status: 401 }
      );
    }

    const newStats: HTBStats = await request.json();
    newStats.lastUpdated = new Date().toISOString();
    
    // Store in memory (will persist until server restart)
    runtimeStats = newStats;
    
    // Log the change for monitoring
    console.log('HTB Stats updated by admin:', newStats);
    
    return NextResponse.json(newStats);
  } catch (error) {
    console.error('Error updating HTB stats:', error);
    return NextResponse.json(
      { error: 'Failed to update stats' }, 
      { status: 500 }
    );
  }
}
