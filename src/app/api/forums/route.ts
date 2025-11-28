import { NextResponse } from 'next/server';
import { NextRequest } from 'next/server';

// Reddit API credentials
const REDDIT_CLIENT_ID = "_in9szoOfEmvTyhhHobFdQ";
const REDDIT_CLIENT_SECRET = "uyNkDPz52_wPfnQkJrrF0sBa08a0Vg";

// Stack Overflow API key
const STACK_OVERFLOW_API_KEY = "rl_42fHk5pV8h3dnuQSFpqW12GB1";

// Cache to store Reddit access token
let redditAccessToken: string | null = null;
let tokenExpiry: number = 0;

async function getRedditToken() {
  if (redditAccessToken && Date.now() < tokenExpiry) {
    return redditAccessToken;
  }

  try {
    const response = await fetch("https://www.reddit.com/api/v1/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": `Basic ${Buffer.from(`${REDDIT_CLIENT_ID}:${REDDIT_CLIENT_SECRET}`).toString("base64")}`,
        "User-Agent": "0xJerrysLab/1.0 by 0xJerry"
      },
      body: "grant_type=client_credentials",
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(`Reddit token fetch failed: ${JSON.stringify(errorData)}`);
    }

    const data = await response.json();
    redditAccessToken = data.access_token;
    tokenExpiry = Date.now() + (data.expires_in - 60) * 1000; // Refresh 1 minute early
    return redditAccessToken;

  } catch (error) {
    console.error("Error getting Reddit token:", error);
    throw error;
  }
}

async function fetchRedditPosts(): Promise<ForumPost[]> {
  try {
    const token = await getRedditToken();
    const subreddits = [
      'netsec', 'cybersecurity', 'hacking', 'redteamsec', 'blackhat', 
      'AskNetsec', 'malware', 'ReverseEngineering', 'pwned', 'HowToHack',
      'computerforensics', 'crypto', 'privacy', 'sysadmin', 'InfoSecNews'
    ];
    const allPosts: ForumPost[] = [];
    
    for (const subreddit of subreddits) {
      try {
        const response = await fetch(`https://oauth.reddit.com/r/${subreddit}/hot?limit=8`, {
          headers: {
            "Authorization": `Bearer ${token}`,
            "User-Agent": "0xJerrysLab/1.0 by 0xJerry"
          }
        });
        
        if (!response.ok) continue;
        
        const data = await response.json();
        const posts = data.data.children.map((child: any) => ({
          title: child.data.title,
          link: `https://reddit.com${child.data.permalink}`,
          upvotes: child.data.ups || 0,
          comments: child.data.num_comments || 0,
          source: "Reddit"
        }));
        
        allPosts.push(...posts);
      } catch (err) {
        console.error(`Error fetching from r/${subreddit}:`, err);
      }
    }
    
    // Sort by upvotes and return top 15
    return allPosts
      .sort((a, b) => b.upvotes - a.upvotes)
      .slice(0, 15);
      
  } catch (error) {
    console.error("Error fetching Reddit posts:", error);
    throw error;
  }
}

async function fetchStackOverflowPosts(): Promise<ForumPost[]> {
  try {
    // Define cybersecurity-related keywords for filtering
    const cyberSecurityKeywords = [
      'vulnerability', 'exploit', 'penetration', 'hacking', 'malware', 'phishing',
      'csrf', 'xss', 'sql injection', 'buffer overflow', 'privilege escalation',
      'firewall', 'intrusion', 'ddos', 'ransomware', 'cryptography', 'forensics',
      'reverse engineering', 'social engineering', 'zero day', 'backdoor'
    ];
    
    // Get current date and calculate date from 6 months ago for recent posts
    const sixMonthsAgo = Math.floor((Date.now() - (6 * 30 * 24 * 60 * 60 * 1000)) / 1000);
    
    // Try multiple approaches with cybersecurity focus
    const approaches = [
      // Approach 1: Security tag with recent posts (last 6 months)
      `https://api.stackexchange.com/2.3/questions?order=desc&sort=creation&tagged=security&site=stackoverflow&pagesize=50&fromdate=${sixMonthsAgo}`,
      // Approach 2: Multiple security-related tags with recent posts
      `https://api.stackexchange.com/2.3/questions?order=desc&sort=creation&tagged=security;authentication;encryption;vulnerability&site=stackoverflow&pagesize=50&fromdate=${sixMonthsAgo}`,
      // Approach 3: Search for cybersecurity terms in title with recent posts
      `https://api.stackexchange.com/2.3/search?order=desc&sort=creation&intitle=security OR vulnerability OR encryption OR authentication&site=stackoverflow&pagesize=50&fromdate=${sixMonthsAgo}`,
      // Approach 4: Fallback without date restriction but with security focus
      `https://api.stackexchange.com/2.3/questions?order=desc&sort=creation&tagged=security&site=stackoverflow&pagesize=30`
    ];
    
    for (const url of approaches) {
      try {
        console.log('Trying Stack Overflow URL:', url);
        
        const response = await fetch(url, {
          headers: {
            "User-Agent": "0xJerrysLab/1.0 by 0xJerry",
            "Accept": "application/json"
          }
        });
        
        if (!response.ok) {
          console.log(`Stack Overflow API request failed with status: ${response.status}`);
          continue;
        }
        
        const data = await response.json();
        console.log('Stack Overflow API response:', { hasItems: !!data.items, itemCount: data.items?.length || 0 });
        
        if (data.items && data.items.length > 0) {
          // Filter posts to include only cybersecurity-related content
          const cyberSecurityPosts = data.items.filter((item: any) => {
            const title = item.title.toLowerCase();
            const tags = (item.tags || []).join(' ').toLowerCase();
            const content = `${title} ${tags}`;
            
            // Check if the post contains cybersecurity-related keywords
            return cyberSecurityKeywords.some(keyword => 
              content.includes(keyword.toLowerCase())
            ) || 
            // Or has security-related tags
            item.tags?.some((tag: string) => 
              ['security', 'authentication', 'encryption', 'vulnerability', 'csrf', 'xss'].includes(tag.toLowerCase())
            );
          });
          
          if (cyberSecurityPosts.length > 0) {
            const posts: ForumPost[] = cyberSecurityPosts.map((item: any) => ({
              title: item.title,
              link: item.link,
              upvotes: item.score || 0,
              comments: item.answer_count || 0,
              source: "Stack Overflow"
            }));
            
            // Return top 10 cybersecurity posts by creation date
            console.log(`Found ${posts.length} cybersecurity-related posts`);
            return posts.slice(0, 10);
          }
        }
      } catch (error) {
        console.log('Error with Stack Overflow approach:', error);
        continue;
      }
    }
    
    // If all approaches fail, return empty array to fall back to mock data
    console.log('All Stack Overflow approaches failed, returning empty array');
    return [];
      
  } catch (error) {
    console.error("Error fetching Stack Overflow posts:", error);
    throw error;
  }
}

interface ForumPost {
  title: string;
  link: string;
  upvotes: number;
  comments: number;
  source: string;
}

// Mock data for demonstration
const mockRedditPosts: ForumPost[] = [
  {
    title: "New Windows LSASS dump technique that bypes most EDRs",
    link: "https://reddit.com/r/netsec/post1",
    upvotes: 247,
    comments: 34,
    source: "Reddit"
  },
  {
    title: "CVE-2024-1337: Remote Code Execution in Popular VPN Client",
    link: "https://reddit.com/r/netsec/post2",
    upvotes: 189,
    comments: 67,
    source: "Reddit"
  },
  {
    title: "Advanced Persistence Techniques for Red Team Operations",
    link: "https://reddit.com/r/redteamsec/post3",
    upvotes: 156,
    comments: 42,
    source: "Reddit"
  },
  {
    title: "Docker Container Breakout via Kernel Exploit",
    link: "https://reddit.com/r/netsec/post4", 
    upvotes: 203,
    comments: 58,
    source: "Reddit"
  },
  {
    title: "Analysis: APT29 latest campaign against government targets",
    link: "https://reddit.com/r/cybersecurity/post5",
    upvotes: 134,
    comments: 29,
    source: "Reddit"
  }
];

const mockStackOverflowPosts: ForumPost[] = [
  {
    title: "How to properly validate user input to prevent XSS in React apps?",
    link: "https://stackoverflow.com/questions/12345",
    upvotes: 89,
    comments: 12,
    source: "Stack Overflow"
  },
  {
    title: "Secure way to implement JWT authentication with refresh tokens",
    link: "https://stackoverflow.com/questions/12346",
    upvotes: 156,
    comments: 23,
    source: "Stack Overflow"
  },
  {
    title: "Best practices for SQL injection prevention in Node.js",
    link: "https://stackoverflow.com/questions/12347",
    upvotes: 234,
    comments: 34,
    source: "Stack Overflow"
  },
  {
    title: "How to implement rate limiting to prevent DDoS attacks?",
    link: "https://stackoverflow.com/questions/12348",
    upvotes: 67,
    comments: 8,
    source: "Stack Overflow"
  },
  {
    title: "Cross-Origin Resource Sharing (CORS) security implications",
    link: "https://stackoverflow.com/questions/12349",
    upvotes: 112,
    comments: 19,
    source: "Stack Overflow"
  }
];

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const source = searchParams.get('source') || 'reddit';
  const fresh = searchParams.get('fresh') === 'true';
  
  try {
    let posts: ForumPost[];
    
    if (source === 'stackoverflow') {
      try {
        posts = await fetchStackOverflowPosts();
        // If no posts were fetched, fall back to mock data
        if (posts.length === 0) {
          console.log('No Stack Overflow posts fetched, using mock data');
          posts = mockStackOverflowPosts;
        }
      } catch (stackOverflowError) {
        console.error('Stack Overflow API failed, falling back to mock data:', stackOverflowError);
        posts = mockStackOverflowPosts;
      }
    } else {
      try {
        posts = await fetchRedditPosts();
        // If no posts were fetched, fall back to mock data
        if (posts.length === 0) {
          console.log('No Reddit posts fetched, using mock data');
          posts = mockRedditPosts;
        }
      } catch (redditError) {
        console.error('Reddit API failed, falling back to mock data:', redditError);
        posts = mockRedditPosts;
      }
    }
    
    return NextResponse.json(posts);
  } catch (error) { 
    console.error('Error in GET /api/forums:', error);
    return NextResponse.json({ error: 'Failed to fetch forum posts' }, { status: 500 });
  }
}
