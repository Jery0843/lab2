// SEO Helper functions for better search engine indexing
import { getSiteUrl } from '@/config/site';

export async function notifySearchEngines(siteUrl?: string) {
  // Auto-detect site URL if not provided
  const finalSiteUrl = siteUrl || 
    (typeof window !== 'undefined' 
      ? `${window.location.protocol}//${window.location.host}`
      : getSiteUrl()
    );
  
  const sitemapUrl = `${finalSiteUrl}/sitemap.xml`;
  const machinesSitemapUrl = `${finalSiteUrl}/sitemap-machines.xml`;
  
  const notifications = [
    // Google
    `https://www.google.com/ping?sitemap=${encodeURIComponent(sitemapUrl)}`,
    `https://www.google.com/ping?sitemap=${encodeURIComponent(machinesSitemapUrl)}`,
    
    // Bing
    `https://www.bing.com/ping?sitemap=${encodeURIComponent(sitemapUrl)}`,
    `https://www.bing.com/ping?sitemap=${encodeURIComponent(machinesSitemapUrl)}`,
  ];

  const results = await Promise.allSettled(
    notifications.map(url => 
      fetch(url, { method: 'GET' }).catch(e => console.warn('Sitemap ping failed:', e))
    )
  );

  console.log('🔍 Notified search engines about sitemap updates');
  return results;
}

export function generateMachineKeywords(machineName: string, os: string, difficulty: string, tags: string[] | string) {
  // Add null checks to prevent errors
  const safeMachineName = machineName || 'machine';
  const safeOs = os || 'linux';
  const safeDifficulty = difficulty || 'medium';
  
  const baseKeywords = [
    'hackthebox',
    'hack the box',
    'HTB',
    'cybersecurity',
    'penetration testing',
    'ethical hacking',
    'writeup',
    'walkthrough',
    'exploit',
    'vulnerability'
  ];

  const machineSpecific = [
    `${safeMachineName.toLowerCase()} hackthebox`,
    `${safeMachineName.toLowerCase()} htb`,
    `${safeMachineName.toLowerCase()} writeup`,
    `${safeMachineName.toLowerCase()} walkthrough`,
    `${safeMachineName.toLowerCase()} ${safeOs.toLowerCase()}`,
    `${safeMachineName.toLowerCase()} ${safeDifficulty.toLowerCase()}`,
    `htb ${safeMachineName.toLowerCase()}`,
    `hackthebox ${safeMachineName.toLowerCase()}`
  ];

  // Handle tags - ensure it's an array
  let tagsArray: string[] = [];
  if (Array.isArray(tags)) {
    tagsArray = tags;
  } else if (typeof tags === 'string') {
    try {
      // Try to parse as JSON array first
      tagsArray = JSON.parse(tags);
    } catch {
      // If parsing fails, split by comma or treat as single tag
      tagsArray = tags.includes(',') ? tags.split(',').map(t => t.trim()) : [tags];
    }
  }

  const tagKeywords = tagsArray.map(tag => [
    `${tag.toLowerCase()} hackthebox`,
    `${tag.toLowerCase()} htb`,
    `${machineName.toLowerCase()} ${tag.toLowerCase()}`
  ]).flat();

  return [...new Set([...baseKeywords, ...machineSpecific, ...tagKeywords])];
}

export function generateMachineDescription(machineName: string, os: string, difficulty: string, tags: string[] | string) {
  // Add null checks to prevent errors
  const safeMachineName = machineName || 'Machine';
  const safeOs = os || 'Linux';
  const safeDifficulty = difficulty || 'Medium';
  
  // Handle tags - ensure it's an array
  let tagsArray: string[] = [];
  if (Array.isArray(tags)) {
    tagsArray = tags;
  } else if (typeof tags === 'string') {
    try {
      // Try to parse as JSON array first
      tagsArray = JSON.parse(tags);
    } catch {
      // If parsing fails, split by comma or treat as single tag
      tagsArray = tags.includes(',') ? tags.split(',').map(t => t.trim()) : [tags];
    }
  }
  
  const primaryTag = tagsArray[0] || 'exploitation';
  
  return `Complete ${safeMachineName} Hack The Box writeup and walkthrough. Learn ${primaryTag.toLowerCase()} techniques on ${safeOs} with this ${safeDifficulty.toLowerCase()} HTB machine. Step-by-step penetration testing guide by 0xJerry.`;
}

export function generateMachineTitle(machineName: string, os: string, difficulty: string) {
  // Add null checks to prevent errors
  const safeMachineName = machineName || 'Machine';
  const safeOs = os || 'Linux';
  const safeDifficulty = difficulty || 'Medium';
  
  return `${safeMachineName} HTB Writeup - ${safeOs} ${safeDifficulty} | 0xJerry's Lab`;
}

// Social media optimization
export function generateMachineStructuredData(
  machine: { id: string; name: string; os: string; difficulty: string; tags: string[] | string; dateCompleted: string | null; writeup: string | null },
  baseUrl?: string
) {
  const siteUrl = baseUrl || getSiteUrl();
  
  // Handle tags - ensure it's an array
  let tagsArray: string[] = [];
  if (Array.isArray(machine.tags)) {
    tagsArray = machine.tags;
  } else if (typeof machine.tags === 'string') {
    try {
      // Try to parse as JSON array first
      tagsArray = JSON.parse(machine.tags);
    } catch {
      // If parsing fails, split by comma or treat as single tag
      tagsArray = machine.tags.includes(',') ? machine.tags.split(',').map(t => t.trim()) : [machine.tags];
    }
  }
  
  // Use fixed date instead of dynamic Date.now() to prevent hydration mismatch
  const currentYear = 2024; // Fixed year to prevent hydration issues
  const publishedDate = machine.dateCompleted || '2024-01-01T00:00:00.000Z';
  
  return {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": `${machine.name} HTB Writeup - ${machine.os} ${machine.difficulty}`,
    "description": generateMachineDescription(machine.name, machine.os, machine.difficulty, machine.tags),
    "author": {
      "@type": "Person",
      "name": "0xJerry",
      "url": siteUrl,
      "sameAs": [
        "https://github.com/0xJerry",
        "https://twitter.com/0xJerry",
        "https://linkedin.com/in/0xjerry"
      ]
    },
    "publisher": {
      "@type": "Organization",
      "name": "0xJerry's Lab",
      "url": siteUrl,
      "logo": {
        "@type": "ImageObject",
        "url": `${siteUrl}/logo.png`,
        "width": 512,
        "height": 512
      }
    },
    "mainEntityOfPage": {
      "@type": "WebPage",
      "@id": `${siteUrl}/machines/htb/${machine.id}`
    },
    "url": `${siteUrl}/machines/htb/${machine.id}`,
    "image": {
      "@type": "ImageObject",
      "url": `${siteUrl}/api/og/machine/${machine.id}`,
      "width": 1200,
      "height": 630
    },
    "datePublished": publishedDate,
    "dateModified": publishedDate,
    "articleSection": "Cybersecurity",
    "keywords": generateMachineKeywords(machine.name, machine.os, machine.difficulty, machine.tags),
    "about": [
      {
        "@type": "Thing",
        "name": "Hack The Box",
        "description": "Online cybersecurity training platform"
      },
      {
        "@type": "Thing",
        "name": "Penetration Testing",
        "description": "Ethical hacking and security assessment"
      },
      {
        "@type": "Thing",
        "name": machine.os,
        "description": `${machine.os} operating system`
      },
      ...tagsArray.map(tag => ({
        "@type": "Thing",
        "name": tag,
        "description": `${tag} cybersecurity technique`
      }))
    ],
    "mentions": [
      {
        "@type": "Organization",
        "name": "Hack The Box",
        "url": "https://hackthebox.com"
      }
    ],
    "inLanguage": "en-US",
    "copyrightHolder": {
      "@type": "Person",
      "name": "0xJerry"
    },
    "copyrightYear": currentYear,
    "educationalLevel": "Advanced",
    "learningResourceType": "Tutorial",
    "teaches": tagsArray.join(', '),
    "difficulty": machine.difficulty,
    "timeRequired": "PT2H", // Estimated 2 hours reading time
    "interactionStatistic": {
      "@type": "InteractionCounter",
      "interactionType": "https://schema.org/ReadAction",
      "userInteractionCount": 0 // This could be dynamic
    }
  };
}

// Social media optimization
export function generateSocialDescription(machineName: string, difficulty: string, tags: string[]) {
  const emoji = difficulty === 'Easy' ? '🟢' : difficulty === 'Medium' ? '🟡' : '🔴';
  const primaryTag = tags[0] || 'exploitation';
  
  return `${emoji} Just pwned ${machineName} on @hackthebox! ${difficulty} ${primaryTag} machine. Full writeup with step-by-step exploitation techniques. #HTB #CyberSecurity #EthicalHacking`;
}

// Generate complete metadata for machine pages
export function generateMachineMetadata(machine: { 
  id: string; 
  name: string; 
  os: string; 
  difficulty: string; 
  tags: string[] | string; 
  dateCompleted: string | null; 
}) {
  const title = generateMachineTitle(machine.name, machine.os, machine.difficulty);
  const description = generateMachineDescription(machine.name, machine.os, machine.difficulty, machine.tags);
  const keywords = generateMachineKeywords(machine.name, machine.os, machine.difficulty, machine.tags);
  const baseUrl = getSiteUrl();
  
  // Handle tags - ensure it's an array
  let tagsArray: string[] = [];
  if (Array.isArray(machine.tags)) {
    tagsArray = machine.tags;
  } else if (typeof machine.tags === 'string') {
    try {
      // Try to parse as JSON array first
      tagsArray = JSON.parse(machine.tags);
    } catch {
      // If parsing fails, split by comma or treat as single tag
      tagsArray = machine.tags.includes(',') ? machine.tags.split(',').map(t => t.trim()) : [machine.tags];
    }
  }
  
  return {
    title,
    description,
    keywords: keywords.join(', '),
    authors: [{ name: '0xJerry', url: baseUrl }],
    creator: '0xJerry',
    publisher: "0xJerry's Lab",
    robots: {
      index: true,
      follow: true,
      googleBot: {
        index: true,
        follow: true,
        'max-video-preview': -1,
        'max-image-preview': 'large' as const,
        'max-snippet': -1,
      },
    },
    openGraph: {
      title,
      description,
      url: `${baseUrl}/machines/htb/${machine.id}`,
      siteName: "0xJerry's Lab",
      images: [
        {
          url: `${baseUrl}/api/og/machine/${machine.id}`,
          width: 1200,
          height: 630,
          alt: `${machine.name} HTB Machine Writeup`,
        },
      ],
      locale: 'en_US',
      type: 'article',
      publishedTime: machine.dateCompleted || undefined,
      authors: ['0xJerry'],
      section: 'Cybersecurity',
      tags: tagsArray,
    },
    twitter: {
      card: 'summary_large_image',
      title,
      description,
      creator: '@0xJerry',
      images: [`${baseUrl}/api/og/machine/${machine.id}`],
    },
    alternates: {
      canonical: `${baseUrl}/machines/htb/${machine.id}`,
    },
    other: {
      'article:section': 'Cybersecurity',
      'article:tag': tagsArray.join(','),
      'article:author': '0xJerry',
      'og:image:alt': `${machine.name} HTB Machine Writeup`,
      'application-name': "0xJerry's Lab",
      'apple-mobile-web-app-title': "0xJerry's Lab",
      'msapplication-TileColor': '#000000',
      'theme-color': '#000000',
    },
  };
}
