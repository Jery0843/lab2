import { NextRequest, NextResponse } from 'next/server';
import machinesData from '@/data/machines.json';
import { getSiteUrl } from '@/config/site';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ slug: string }> }
) {
  const { slug } = await params;
  const siteUrl = getSiteUrl();
  const displayUrl = siteUrl.replace('https://', '').replace('http://', '');
  
  // Find the machine
  const machine = machinesData.find(m => 
    m.id.toLowerCase() === slug.toLowerCase() || 
    m.name.toLowerCase().replace(/\s+/g, '-') === slug.toLowerCase()
  );

  if (!machine) {
    return new NextResponse('Machine not found', { status: 404 });
  }

  // Create a simple SVG-based Open Graph image
  const svg = `
    <svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="bgGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style="stop-color:#0a0a0a;stop-opacity:1" />
          <stop offset="100%" style="stop-color:#1a1a1a;stop-opacity:1" />
        </linearGradient>
        <linearGradient id="accentGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" style="stop-color:#00ff41;stop-opacity:1" />
          <stop offset="100%" style="stop-color:#00d4aa;stop-opacity:1" />
        </linearGradient>
      </defs>
      
      <!-- Background -->
      <rect width="1200" height="630" fill="url(#bgGradient)"/>
      
      <!-- Grid pattern -->
      <defs>
        <pattern id="grid" width="50" height="50" patternUnits="userSpaceOnUse">
          <path d="M 50 0 L 0 0 0 50" fill="none" stroke="#00ff41" stroke-width="0.5" opacity="0.1"/>
        </pattern>
      </defs>
      <rect width="1200" height="630" fill="url(#grid)"/>
      
      <!-- Top border -->
      <rect x="0" y="0" width="1200" height="4" fill="url(#accentGradient)"/>
      
      <!-- Main content area -->
      <rect x="60" y="80" width="1080" height="470" fill="none" stroke="#00ff41" stroke-width="2" opacity="0.3"/>
      
      <!-- Machine name -->
      <text x="100" y="180" font-family="monospace" font-size="64" font-weight="bold" fill="#00ff41">
        ${machine.name}
      </text>
      
      <!-- Subtitle -->
      <text x="100" y="220" font-family="monospace" font-size="24" fill="#ffffff" opacity="0.8">
        Hack The Box Machine Writeup
      </text>
      
      <!-- Machine details -->
      <text x="100" y="280" font-family="monospace" font-size="20" fill="#00d4aa">
        OS: ${machine.os} | Difficulty: ${machine.difficulty} | Status: ${machine.status}
      </text>
      
      <!-- Tags -->
      <text x="100" y="320" font-family="monospace" font-size="16" fill="#ffffff" opacity="0.7">
        Tags: ${machine.tags.slice(0, 3).join(' • ')}
      </text>
      
      <!-- Brand -->
      <text x="100" y="480" font-family="monospace" font-size="28" font-weight="bold" fill="#00ff41">
        0xJerry's Lab
      </text>
      
      <!-- URL -->
      <text x="100" y="510" font-family="monospace" font-size="18" fill="#ffffff" opacity="0.6">
        ${displayUrl}/machines/${slug}
      </text>
      
      <!-- Decorative elements -->
      <circle cx="1000" cy="150" r="60" fill="none" stroke="#00ff41" stroke-width="2" opacity="0.3"/>
      <circle cx="1000" cy="150" r="40" fill="none" stroke="#00d4aa" stroke-width="1" opacity="0.2"/>
      <circle cx="1000" cy="150" r="20" fill="#00ff41" opacity="0.1"/>
      
      <!-- HTB style brackets -->
      <path d="M 50 100 L 30 100 L 30 530 L 50 530" stroke="#00ff41" stroke-width="3" fill="none"/>
      <path d="M 1150 100 L 1170 100 L 1170 530 L 1150 530" stroke="#00ff41" stroke-width="3" fill="none"/>
    </svg>
  `;

  return new NextResponse(svg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=31536000, immutable',
    },
  });
}
