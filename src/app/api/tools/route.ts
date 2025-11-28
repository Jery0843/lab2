import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

interface Tool {
  id: string;
  name: string;
  description: string;
  link?: string;
  code?: string;
  type?: string;
  tags: string[];
  lastUpdated?: string;
  stars?: number;
  language?: string;
}

interface GitHubRepo {
  name: string;
  description: string;
  html_url: string;
  stargazers_count: number;
  language: string;
  updated_at: string;
  topics: string[];
}

// Popular security tool repositories
const SECURITY_REPOS = [
  'danielmiessler/SecLists',
  'swisskyrepo/PayloadsAllTheThings',
  'OWASP/CheatSheetSeries',
  'carlospolop/PEASS-ng',
  'rebootuser/LinEnum',
  'pentestmonkey/php-reverse-shell',
  'PowerShellMafia/PowerSploit',
  'trustedsec/ptf',
  'sqlmapproject/sqlmap',
  'vanhauser-thc/thc-hydra',
  'volatilityfoundation/volatility',
  'rapid7/metasploit-framework',
  'nmap/nmap',
  'aircrack-ng/aircrack-ng',
  'SecureAuthCorp/impacket'
];

// Fetch tools from GitHub API
async function fetchGitHubTools(): Promise<Tool[]> {
  const tools: Tool[] = [];
  
  try {
    for (const repo of SECURITY_REPOS.slice(0, 10)) { // Limit to avoid rate limiting
      try {
        const response = await fetch(`https://api.github.com/repos/${repo}?t=${Date.now()}`, {
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': '0xjerrys-lab',
            'Cache-Control': 'no-cache'
          }
        });
        
        if (response.ok) {
          const repoData: GitHubRepo = await response.json();
          
          tools.push({
            id: repo.replace('/', '-').toLowerCase(),
            name: repoData.name,
            description: repoData.description || 'Security tool repository',
            link: repoData.html_url,
            tags: categorizeRepo(repoData),
            lastUpdated: new Date(repoData.updated_at).toISOString(),
            stars: repoData.stargazers_count,
            language: repoData.language || 'Multiple'
          });
        }
      } catch (error) {
        console.warn(`Failed to fetch repo ${repo}:`, error);
      }
    }
  } catch (error) {
    console.error('Error fetching GitHub tools:', error);
  }
  
  return tools;
}

// Categorize repository based on name and topics
function categorizeRepo(repo: GitHubRepo): string[] {
  const name = repo.name.toLowerCase();
  const description = (repo.description || '').toLowerCase();
  const topics = repo.topics || [];
  const tags: string[] = [];
  
  // Language-based tags
  if (repo.language) {
    tags.push(repo.language);
  }
  
  // Tool-specific tags
  if (name.includes('payload') || name.includes('shell')) tags.push('Payload');
  if (name.includes('enum') || name.includes('recon')) tags.push('Reconnaissance');
  if (name.includes('exploit') || name.includes('metasploit')) tags.push('Exploitation');
  if (name.includes('priv') || name.includes('escalation')) tags.push('Privilege Escalation');
  if (name.includes('web') || name.includes('sql')) tags.push('Web');
  if (name.includes('windows') || description.includes('windows')) tags.push('Windows');
  if (name.includes('linux') || description.includes('linux')) tags.push('Linux');
  if (name.includes('network') || name.includes('nmap')) tags.push('Networking');
  if (name.includes('forensic') || name.includes('volatility')) tags.push('Forensics');
  if (name.includes('crack') || name.includes('hash')) tags.push('Cracking');
  
  // Topic-based tags
  topics.forEach(topic => {
    if (topic === 'penetration-testing') tags.push('Pentesting');
    if (topic === 'security') tags.push('Security');
    if (topic === 'cybersecurity') tags.push('Cybersecurity');
  });
  
  return tags.length > 0 ? [...new Set(tags)] : ['Security'];
}

// Fetch static tools from JSON file
async function fetchStaticTools(): Promise<Tool[]> {
  try {
    const toolsFilePath = path.join(process.cwd(), 'src', 'data', 'tools.json');
    const toolsData = fs.readFileSync(toolsFilePath, 'utf-8');
    return JSON.parse(toolsData);
  } catch (error) {
    console.error('Error reading static tools:', error);
    return [];
  }
}

// Merge and deduplicate tools
function mergeTools(staticTools: Tool[], dynamicTools: Tool[]): Tool[] {
  const toolMap = new Map<string, Tool>();
  
  // Add static tools first
  staticTools.forEach(tool => {
    toolMap.set(tool.id, tool);
  });
  
  // Add dynamic tools (will overwrite static if same ID)
  dynamicTools.forEach(tool => {
    toolMap.set(tool.id, tool);
  });
  
  return Array.from(toolMap.values());
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const source = searchParams.get('source') || 'all';
  const fresh = searchParams.get('fresh') === 'true';
  
  // Add cache-busting headers
  const headers = {
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  };
  
  try {
    let tools: Tool[] = [];
    
    if (source === 'static') {
      // Only fetch static tools
      tools = await fetchStaticTools();
    } else if (source === 'github') {
      // Only fetch GitHub tools
      tools = await fetchGitHubTools();
    } else {
      // Fetch both and merge
      const [staticTools, githubTools] = await Promise.all([
        fetchStaticTools(),
        fetchGitHubTools() // Always fetch fresh GitHub data to show latest tools
      ]);
      
      tools = mergeTools(staticTools, githubTools);
    }
    
    // Sort by stars (if available) and then by name
    tools.sort((a, b) => {
      if (a.stars && b.stars) {
        return b.stars - a.stars;
      }
      return a.name.localeCompare(b.name);
    });
    
    const response = NextResponse.json({
      tools,
      meta: {
        total: tools.length,
        lastUpdated: new Date().toISOString(),
        source
      }
    });
    
    // Set cache-busting headers
    Object.entries(headers).forEach(([key, value]) => {
      response.headers.set(key, value);
    });
    
    return response;
    
  } catch (error) {
    console.error('Error fetching tools:', error);
    
    // Fallback to static tools on error
    try {
      const staticTools = await fetchStaticTools();
      return NextResponse.json({
        tools: staticTools,
        meta: {
          total: staticTools.length,
          lastUpdated: new Date().toISOString(),
          source: 'static-fallback',
          error: 'Failed to fetch latest tools, showing cached data'
        }
      });
    } catch (fallbackError) {
      return NextResponse.json(
        { error: 'Unable to fetch tools data.' }, 
        { status: 500 }
      );
    }
  }
}

