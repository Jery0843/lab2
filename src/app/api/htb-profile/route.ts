import fs from 'fs';
import path from 'path';
import { NextResponse } from 'next/server';

interface HTBStats {
  machinesPwned: number;
  globalRanking: number;
  finalScore: number;
  htbRank: string;
  lastUpdated: string;
}

const statsFilePath = path.join(process.cwd(), 'src/data/htb-stats.json');

// Fallback data in case file reading fails
const fallbackStats: HTBStats = {
  machinesPwned: 11,
  globalRanking: 891,
  finalScore: 164,
  htbRank: 'Hacker',
  lastUpdated: new Date().toISOString()
};

async function getHTBStats(): Promise<HTBStats> {
  try {
    const fileContents = fs.readFileSync(statsFilePath, 'utf-8');
    const stats = JSON.parse(fileContents);
    return stats;
  } catch (error) {
    console.error('Error reading HTB stats file:', error);
    return fallbackStats;
  }
}

export async function GET() {
  try {
    const stats = await getHTBStats();
    return NextResponse.json(stats);
  } catch (error) {
    console.error('HTB Profile API error:', error);
    
    // Return fallback data on error
    return NextResponse.json({
      ...fallbackStats,
      lastUpdated: new Date().toISOString(),
      error: 'Failed to fetch stats from file'
    });
  }
}
