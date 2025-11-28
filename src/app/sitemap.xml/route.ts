import { NextResponse } from 'next/server';
import { HTBMachinesDB, CTFWriteupsDB } from '@/lib/db';
import machinesData from '@/data/machines.json';

export async function GET(request: Request) {
  // Auto-detect the base URL from the request
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;
  const currentDate = new Date().toISOString();

  const toW3CDate = (value: any): string => {
    if (!value) return currentDate;
    try {
      // Normalize common DB format "YYYY-MM-DD HH:mm:ss"
      const str = String(value).trim();
      const normalized = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(str)
        ? str.replace(' ', 'T') + 'Z'
        : str;
      const d = new Date(normalized);
      return isNaN(d.getTime()) ? currentDate : d.toISOString();
    } catch {
      return currentDate;
    }
  };
  
  // Static pages with their priorities and change frequencies
  const staticPages = [
    {
      url: '',
      lastModified: currentDate,
      changeFrequency: 'daily',
      priority: 1.0
    },
    {
      url: '/about',
      lastModified: currentDate,
      changeFrequency: 'monthly',
      priority: 0.8
    },
    {
      url: '/machines',
      lastModified: currentDate,
      changeFrequency: 'weekly',
      priority: 0.9
    },
    {
      url: '/machines/htb',
      lastModified: currentDate,
      changeFrequency: 'weekly',
      priority: 0.9
    },
    {
      url: '/machines/thm',
      lastModified: currentDate,
      changeFrequency: 'weekly',
      priority: 0.9
    },
    {
      url: '/tools',
      lastModified: currentDate,
      changeFrequency: 'weekly',
      priority: 0.9
    },
    {
      url: '/ctf',
      lastModified: currentDate,
      changeFrequency: 'weekly',
      priority: 0.9
    },
    {
      url: '/news',
      lastModified: currentDate,
      changeFrequency: 'daily',
      priority: 0.7
    },
    {
      url: '/forums',
      lastModified: currentDate,
      changeFrequency: 'daily',
      priority: 0.6
    },
    {
      url: '/membership',
      lastModified: currentDate,
      changeFrequency: 'monthly',
      priority: 0.7
    },
    {
      url: '/privacy',
      lastModified: currentDate,
      changeFrequency: 'yearly',
      priority: 0.3
    },
    {
      url: '/terms',
      lastModified: currentDate,
      changeFrequency: 'yearly',
      priority: 0.3
    }
  ];

  // Fetch HTB machines dynamically
  let htbMachines = machinesData as any[];
  try {
    const machinesDB = new HTBMachinesDB();
    const dbMachines = await machinesDB.getAllMachines();
    if (dbMachines && dbMachines.length > 0) {
      htbMachines = dbMachines as any[];
    }
  } catch (e) {
    // fallback to static
  }

  // Fetch THM rooms dynamically
  let thmRooms: any[] = [];
  try {
    const { THMRoomsDB } = await import('@/lib/db');
    const thmDB = new THMRoomsDB();
    const dbRooms = await thmDB.getAllRooms();
    if (dbRooms && dbRooms.length > 0) {
      thmRooms = dbRooms;
    }
  } catch (e) {
    // fallback to empty
  }

  // Fetch CTF writeups dynamically
  let ctfWriteups: any[] = [];
  try {
    const ctfDB = new CTFWriteupsDB();
    const dbWriteups = await ctfDB.getAllWriteups();
    if (dbWriteups && dbWriteups.length > 0) {
      ctfWriteups = dbWriteups as any[];
    }
  } catch (e) {
    // fallback to empty
  }

  const htbMachineUrls = htbMachines
    .map((machine: any) => {
      const lastModified = toW3CDate(machine.updated_at || machine.created_at || machine.dateCompleted || currentDate);
      const changeFreq = machine.status === 'Completed' ? 'monthly' : 'weekly';
      const priority = machine.status === 'Completed' ? '0.9' : '0.7';
      const loc = `${baseUrl}/machines/htb/${machine.id}`;
      return `  <url>
    <loc>${loc}</loc>
    <lastmod>${lastModified}</lastmod>
    <changefreq>${changeFreq}</changefreq>
    <priority>${priority}</priority>
  </url>`;
    })
    .join('\n');

  const thmRoomUrls = thmRooms
    .map((room: any) => {
      const lastModified = toW3CDate(room.updated_at || room.created_at || room.date_completed || currentDate);
      const changeFreq = room.status === 'Completed' ? 'monthly' : 'weekly';
      const priority = room.status === 'Completed' ? '0.9' : '0.7';
      const loc = `${baseUrl}/machines/thm/${room.slug || room.id}`;
      return `  <url>
    <loc>${loc}</loc>
    <lastmod>${lastModified}</lastmod>
    <changefreq>${changeFreq}</changefreq>
    <priority>${priority}</priority>
  </url>`;
    })
    .join('\n');

  const ctfWriteupUrls = ctfWriteups
    .map((writeup: any) => {
      const lastModified = toW3CDate(writeup.updated_at || writeup.created_at || writeup.date_completed || currentDate);
      const changeFreq = writeup.status === 'Completed' ? 'monthly' : 'weekly';
      const priority = writeup.status === 'Completed' ? '0.9' : '0.7';
      const loc = `${baseUrl}/ctf/${writeup.slug}`;
      return `  <url>
    <loc>${loc}</loc>
    <lastmod>${lastModified}</lastmod>
    <changefreq>${changeFreq}</changefreq>
    <priority>${priority}</priority>
  </url>`;
    })
    .join('\n');

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" 
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
${staticPages
  .map(
    (page) => `  <url>
    <loc>${baseUrl}${page.url}</loc>
    <lastmod>${page.lastModified}</lastmod>
    <changefreq>${page.changeFrequency}</changefreq>
    <priority>${page.priority}</priority>
  </url>`
  )
  .join('\n')}
${htbMachineUrls}
${thmRoomUrls}
${ctfWriteupUrls}
</urlset>`;

  return new NextResponse(sitemap, {
    headers: {
      'Content-Type': 'application/xml',
      'Cache-Control': 'public, max-age=3600, s-maxage=3600', // Cache for 1 hour
    },
  });
}
