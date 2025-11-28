import { NextResponse } from 'next/server';
import Parser from 'rss-parser';

interface NewsItem {
  title: string;
  link: string;
  summary: string;
  timestamp: string;
  source: string;
  tags: string[];
  pubDate?: string; // ISO date string for sorting
}

// Mock data for demonstration - replace with actual RSS parsing
const mockNews: NewsItem[] = [
  {
    title: "Major Dark Web Marketplace 'Hydra' Successor Emerges with Enhanced Security",
    link: "https://example.com/news1",
    summary: "Law enforcement agencies report the emergence of a new dark web marketplace following the takedown of Hydra, implementing advanced operational security measures...",
    timestamp: "2 hours ago",
    source: "ZDNet Security",
    tags: ["Dark Web", "Underground", "Cybercrime"],
    pubDate: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
  },
  {
    title: "Tor Network Usage Surges 300% Following Global Surveillance Revelations",
    link: "https://example.com/news2", 
    summary: "Privacy advocates report massive increase in Tor browser usage as users seek anonymity following recent government surveillance disclosures...",
    timestamp: "4 hours ago",
    source: "Ars Technica Security",
    tags: ["Deep Web", "Anonymous Networks", "Privacy"],
    pubDate: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString()
  },
  {
    title: "Critical Apache Struts Vulnerability CVE-2024-1337",
    link: "https://example.com/news3", 
    summary: "Apache has released patches for a critical remote code execution vulnerability in Struts framework versions 2.5.0 to 2.5.32...",
    timestamp: "6 hours ago",
    source: "Exploit Database",
    tags: ["Vulnerability", "RCE", "Exploit"],
    pubDate: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString()
  },
  {
    title: "Underground Forums Selling Access to Compromised Corporate Networks",
    link: "https://example.com/news4",
    summary: "Cybersecurity researchers discovered active marketplaces on the dark web selling initial access to Fortune 500 company networks for cryptocurrency...",
    timestamp: "8 hours ago",
    source: "Help Net Security",
    tags: ["Dark Web", "Data Theft", "Corporate Security"],
    pubDate: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString()
  },
  {
    title: "New Stealer Malware Targets Cryptocurrency Wallets on Hidden Services",
    link: "https://example.com/news5",
    summary: "Malware analysts have identified a sophisticated credential harvesting campaign specifically targeting users of underground cryptocurrency exchanges...",
    timestamp: "12 hours ago",
    source: "Malwarebytes Labs", 
    tags: ["Malware", "Data Theft", "Crypto", "Deep Web"],
    pubDate: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString()
  },
  {
    title: "Law Enforcement Disrupts International Cybercrime Network Using I2P",
    link: "https://example.com/news6",
    summary: "International police operation successfully infiltrates and disrupts a major cybercriminal organization operating across multiple anonymous networks...",
    timestamp: "1 day ago",
    source: "Bad Cyber", 
    tags: ["Anonymous Networks", "Law Enforcement", "Underground"],
    pubDate: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
  }
];

async function fetchRSSFeed(url: string, sourceName: string): Promise<NewsItem[]> {
  const parser = new Parser({
    timeout: 10000, // 10 second timeout
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; CyberSecurityNewsBot/1.0)',
      'Accept': 'application/rss+xml, application/xml, text/xml'
    }
  });
  
  try {
    console.log(`Fetching RSS from ${sourceName}...`);
    const feed = await parser.parseURL(url);
    
    if (!feed.items || feed.items.length === 0) {
      console.warn(`No items found in RSS feed for ${sourceName}`);
      return [];
    }
    
    return feed.items.slice(0, 5).map(item => {
      const pubDate = item.pubDate ? new Date(item.pubDate) : new Date();
      return {
        title: item.title || 'No title',
        link: item.link || '#',
        summary: (item.contentSnippet || item.summary || item.content || 'No summary available')
          .replace(/<[^>]*>/g, '') // Strip HTML tags
          .substring(0, 200) + '...',
        timestamp: getTimeAgo(pubDate),
        source: sourceName,
        tags: extractTags(item.title || '', item.contentSnippet || item.summary || ''),
        pubDate: pubDate.toISOString() // Add ISO date for proper sorting
      };
    });
  } catch (error) {
    console.error(`Error fetching RSS from ${sourceName}:`, error);
    return [];
  }
}

function getTimeAgo(date: Date): string {
  const now = new Date();
  const diffInMs = now.getTime() - date.getTime();
  const diffInHours = Math.floor(diffInMs / (1000 * 60 * 60));
  const diffInDays = Math.floor(diffInHours / 24);
  
  if (diffInHours < 1) return 'Just now';
  if (diffInHours < 24) return `${diffInHours} hours ago`;
  if (diffInDays === 1) return '1 day ago';
  if (diffInDays < 7) return `${diffInDays} days ago`;
  return date.toLocaleDateString();
}

function parseTimeAgo(timestamp: string): number {
  const now = Date.now();
  
  if (timestamp === 'Just now') return now;
  
  // Handle "X hours ago" format
  const hoursMatch = timestamp.match(/(\d+)\s+hours?\s+ago/i);
  if (hoursMatch) {
    return now - (parseInt(hoursMatch[1]) * 60 * 60 * 1000);
  }
  
  // Handle "X days ago" format
  const daysMatch = timestamp.match(/(\d+)\s+days?\s+ago/i);
  if (daysMatch) {
    return now - (parseInt(daysMatch[1]) * 24 * 60 * 60 * 1000);
  }
  
  // Handle "X minutes ago" format
  const minutesMatch = timestamp.match(/(\d+)\s+minutes?\s+ago/i);
  if (minutesMatch) {
    return now - (parseInt(minutesMatch[1]) * 60 * 1000);
  }
  
  // Handle date formats like "31/7/2025", "10/7/2025"
  const dateSlashMatch = timestamp.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (dateSlashMatch) {
    const day = parseInt(dateSlashMatch[1]);
    const month = parseInt(dateSlashMatch[2]) - 1; // JavaScript months are 0-indexed
    const year = parseInt(dateSlashMatch[3]);
    return new Date(year, month, day).getTime();
  }
  
  // Try to parse as standard date string
  const parsedDate = Date.parse(timestamp);
  if (!isNaN(parsedDate)) {
    return parsedDate;
  }
  
  return now; // Default to now if parsing fails
}

function extractTags(title: string, content: string): string[] {
  const text = (title + ' ' + content).toLowerCase();
  const tagMap: { [key: string]: string } = {
    // Dark Web & Deep Web
    'dark.web|darkweb|dark.net|darknet': 'Dark Web',
    'deep.web|deepweb|hidden.service|onion': 'Deep Web',
    'tor|i2p|freenet|hidden.market': 'Anonymous Networks',
    'underground|black.market|darkmarket': 'Underground',
    'cybercrime|cyber.crime|criminal': 'Cybercrime',
    
    // Threat Intelligence
    'threat.intelligence|threat.actor|apt': 'Threat Intel',
    'attribution|threat.hunting|ioc': 'Attribution',
    'indicators.of.compromise|iocs': 'IOCs',
    
    // Vulnerabilities & Exploits
    'zero.day|0.day': 'Zero-Day',
    'vulnerability|vuln|cve': 'Vulnerability',
    'exploit|poc|proof.of.concept': 'Exploit',
    'rce|remote.code.execution': 'RCE',
    'sql.injection|sqli': 'SQLi',
    'xss|cross.site': 'XSS',
    
    // Malware & Attacks
    'malware|trojan|ransomware|virus': 'Malware',
    'backdoor|rat|remote.access': 'Backdoor',
    'botnet|c2|command.control': 'Botnet',
    'cryptojacking|mining|monero': 'Cryptojacking',
    'stealer|infostealer|credential': 'Data Theft',
    
    // Social Engineering
    'phishing|spear.phishing|whaling': 'Phishing',
    'social.engineering|pretexting': 'Social Engineering',
    'business.email.compromise|bec': 'BEC',
    
    // Platforms & Technologies
    'windows|microsoft': 'Windows',
    'linux|unix': 'Linux',
    'android|mobile': 'Mobile',
    'ios|iphone|apple': 'iOS',
    'docker|container': 'Container',
    'kubernetes|k8s': 'Kubernetes',
    'cloud|aws|azure|gcp': 'Cloud',
    'scada|ics|industrial': 'Industrial',
    
    // Attack Types
    'ddos|denial.of.service': 'DDoS',
    'insider.threat|insider': 'Insider Threat',
    'supply.chain|third.party': 'Supply Chain',
    'watering.hole|strategic.compromise': 'Watering Hole',
    
    // Emerging Technologies
    'ai|artificial.intelligence|machine.learning': 'AI',
    'blockchain|crypto|bitcoin|ethereum': 'Crypto',
    'iot|internet.of.things': 'IoT',
    '5g|edge.computing': '5G/Edge',
    
    // Regional Threats
    'russia|russian|apt28|apt29': 'Russian Threats',
    'china|chinese|apt1|apt40': 'Chinese Threats',
    'north.korea|lazarus|apt38': 'North Korean Threats',
    'iran|iranian|apt33|apt35': 'Iranian Threats'
  };
  
  const tags: string[] = [];
  for (const [pattern, tag] of Object.entries(tagMap)) {
    const regex = new RegExp(pattern.replace(/\./g, '\\s*'), 'i');
    if (regex.test(text) && !tags.includes(tag)) {
      tags.push(tag);
    }
  }
  
  return tags.length > 0 ? tags.slice(0, 4) : ['Security'];
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);  
  const fresh = searchParams.get('fresh') === 'true';
  
  try {
    const feeds = [
      // Traditional Cybersecurity News (Working)
      { url: 'https://feeds.feedburner.com/TheHackersNews', name: 'The Hacker News' },
      { url: 'https://krebsonsecurity.com/feed/', name: 'Krebs on Security' },
      { url: 'https://www.darkreading.com/rss.xml', name: 'Dark Reading' },
      { url: 'https://threatpost.com/feed/', name: 'Threatpost' },
      
      // Security Research & Intelligence (Working)
      { url: 'https://www.recordedfuture.com/feed', name: 'Recorded Future' },
      { url: 'https://unit42.paloaltonetworks.com/feed/', name: 'Unit 42' },
      { url: 'https://research.checkpoint.com/feed/', name: 'Check Point Research' },
      
      // Dark Web & Underground Intelligence (Working Sources)
      { url: 'https://www.bleepingcomputer.com/feed/', name: 'BleepingComputer' },
      { url: 'https://www.securityweek.com/feed', name: 'SecurityWeek' },
      { url: 'https://www.infosecurity-magazine.com/rss/news/', name: 'Infosecurity Magazine' },
      { url: 'https://badcyber.com/feed/', name: 'Bad Cyber' },
      
      // Malware & Incident Response (Working)
      { url: 'https://blog.malwarebytes.com/feed/', name: 'Malwarebytes Labs' },
      { url: 'https://www.crowdstrike.com/blog/feed/', name: 'CrowdStrike' },
      { url: 'https://www.cybereason.com/blog/rss.xml', name: 'Cybereason' },
      { url: 'https://www.sentinelone.com/blog/rss/', name: 'SentinelOne Labs' },
      
      // Vulnerability Research (Working)
      { url: 'https://www.exploit-db.com/rss.xml', name: 'Exploit Database' },
      { url: 'https://blog.qualys.com/feed', name: 'Qualys Security' },
      
      // Enterprise Security & Threat Intelligence (Working)
      { url: 'https://www.helpnetsecurity.com/feed/', name: 'Help Net Security' },
      { url: 'https://www.csoonline.com/feed/', name: 'CSO Online' },
      
      // Additional Sources with Dark Web Coverage
      { url: 'https://feeds.feedburner.com/eset/blog', name: 'ESET Research' },
      { url: 'https://www.welivesecurity.com/feed/', name: 'WeLiveSecurity' },
      { url: 'https://www.schneier.com/blog/atom.xml', name: 'Schneier on Security' },
      { url: 'https://www.troyhunt.com/rss/', name: 'Troy Hunt' },
      
      // Cybercrime & Underground Activity Coverage
      { url: 'https://www.zdnet.com/topic/security/rss.xml', name: 'ZDNet Security' },
      { url: 'https://arstechnica.com/security/feed/', name: 'Ars Technica Security' }
    ];
    
    const allNews: NewsItem[] = [];
    const fetchPromises: Promise<NewsItem[]>[] = [];
    let successfulFeeds = 0;
    let failedFeeds = 0;
    
    // Fetch from all RSS feeds in parallel for better performance
    for (const feed of feeds) {
      fetchPromises.push(
        fetchRSSFeed(feed.url, feed.name).then(items => {
          if (items.length > 0) {
            successfulFeeds++;
            console.log(`✅ ${feed.name}: ${items.length} items`);
          } else {
            failedFeeds++;
            console.log(`⚠️ ${feed.name}: no items found`);
          }
          return items;
        }).catch(error => {
          failedFeeds++;
          console.error(`❌ ${feed.name}: ${error.message}`);
          return []; // Return empty array on error
        })
      );
    }
    
    // Wait for all feeds to complete (or timeout)
    const results = await Promise.allSettled(fetchPromises);
    
    // Collect all successful results
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        allNews.push(...result.value);
      } else {
        console.error(`Feed ${feeds[index].name} failed:`, result.reason);
      }
    });
    
    // Sort by publication date (newest first) and limit to 20 items
    const sortedNews = allNews
      .filter(item => item.title && item.link) // Filter out invalid items
      .sort((a, b) => {
        // Use pubDate for sorting if available, otherwise fall back to timestamp parsing
        if (a.pubDate && b.pubDate) {
          return new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime(); // Newest first
        }
        
        // Fallback to timestamp parsing for mock data or items without pubDate
        const timeA = parseTimeAgo(a.timestamp);
        const timeB = parseTimeAgo(b.timestamp);
        return timeB - timeA; // Newest first
      })
      .slice(0, 20);
    
    console.log(`📊 Feed Summary: ${successfulFeeds} successful, ${failedFeeds} failed out of ${feeds.length} total`);
    console.log(`Successfully fetched ${sortedNews.length} news items from working sources`);
    
    // If no news was fetched, fall back to mock data
    if (sortedNews.length === 0) {
      console.log('No RSS feeds available, using mock data');
      return NextResponse.json(mockNews);
    }
    
    return NextResponse.json(sortedNews);
  } catch (error) {
    console.error('Error in news API:', error);
    // Fallback to mock data on error
    return NextResponse.json(mockNews);
  }
}
