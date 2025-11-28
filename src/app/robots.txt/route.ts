import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  // Auto-detect the base URL from the request
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const robots = `User-agent: *
Allow: /

# Block access to admin areas
Disallow: /admin/
Disallow: /api/admin/

# Block access to sensitive areas
Disallow: /api/
Disallow: /_next/
Disallow: /static/

# Allow specific API endpoints that provide content
Allow: /api/tools
Allow: /api/machines
Allow: /api/news
Allow: /api/cve

# Crawl delay (optional - prevents overloading server)
Crawl-delay: 1

# Sitemap location
Sitemap: ${baseUrl}/sitemap.xml
Sitemap: ${baseUrl}/sitemap-machines.xml
Sitemap: ${baseUrl}/sitemap-tools.xml

# Block specific bots if needed (example)
# User-agent: BadBot
# Disallow: /`;

  return new NextResponse(robots, {
    headers: {
      'Content-Type': 'text/plain',
      'Cache-Control': 'public, max-age=86400, s-maxage=86400', // Cache for 24 hours
    },
  });
}
