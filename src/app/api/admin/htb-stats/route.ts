import fs from 'fs';
import path from 'path';
import { NextResponse, NextRequest } from 'next/server';

interface HTBStats {
  machinesPwned: number;
  globalRanking: number;
  finalScore: number;
  htbRank: string;
  lastUpdated: string;
}

const statsFilePath = path.join(process.cwd(), 'src/data/htb-stats.json');

export async function GET() {
  try {
    const fileContents = fs.readFileSync(statsFilePath, 'utf-8');
    const stats = JSON.parse(fileContents);
    return NextResponse.json(stats);
  } catch (error) {
    console.error('Error reading HTB stats file:', error);
    return NextResponse.json({
      machinesPwned: 11,
      globalRanking: 891,
      finalScore: 164,
      htbRank: 'Hacker',
      lastUpdated: new Date().toISOString(),
      error: 'Failed to read stats, showing defaults'
    });
  }
}

export async function POST(request: NextRequest) {
  try {
    const newStats: HTBStats = await request.json();
    fs.writeFileSync(statsFilePath, JSON.stringify(newStats, null, 2));
    return NextResponse.json(newStats);
  } catch (error) {
    console.error('Error updating HTB stats file:', error);
    return NextResponse.json({
      error: 'Failed to update stats'
    }, { status: 500 });
  }
}
