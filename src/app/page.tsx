'use client';

export const dynamic = 'force-dynamic';

import Layout from '@/components/Layout';
import Head from 'next/head';
import Link from 'next/link';
import { FaSkull, FaCode, FaBug, FaShieldAlt, FaTerminal } from 'react-icons/fa';
import { useEffect, useState } from 'react';
import machinesData from '@/data/machines.json';
import SubscriberSpotlight from '@/components/SubscriberSpotlight';

interface Tool {
  id: string;
  name: string;
  description: string;
  link?: string;
  tags: string[];
  stars?: number;
  language?: string;
  lastUpdated?: string;
  publishedAt?: string;
}

interface Machine {
  id: string;
  name: string;
  os: string;
  difficulty: string;
  status: string;
  dateCompleted: string | null;
  tags: string[];
  writeup: string | null;
  platform?: 'HTB' | 'THM'; // Add platform identifier
}

interface THMRoom {
  id: string;
  title: string;
  name: string;
  difficulty: string;
  status: string;
  dateCompleted: string | null;
  date_completed: string | null;
  tags: string | string[];
  writeup: string | null;
  roomCode: string;
  points: number;
}

interface CTFWriteup {
  id: string;
  title: string;
  slug: string;
  ctfName: string;
  category: string;
  difficulty: string;
  points?: number;
  status: string;
  dateCompleted?: string | null;
  tags: string[];
  writeup?: string | null;
  summary?: string | null;
  platform?: 'CTF';
}

type WriteupItem = Machine | CTFWriteup;

interface HTBStats {
  machinesPwned: number;
  globalRanking: number;
  finalScore: number;
  htbRank: string;
  lastUpdated: string;
}

interface THMStats {
  thm_rank: string;
  rooms_completed: number;
  streak: number;
  badges: Array<{ name: string; icon: string; description: string }>;
  last_updated: string;
}

export default function Home() {
  const [displayText, setDisplayText] = useState('');
  const [, setMachines] = useState<Machine[]>([]);
  const [latestMachines, setLatestMachines] = useState<WriteupItem[]>([]);
  const [ctfWriteups, setCTFWriteups] = useState<CTFWriteup[]>([]);
  const [tools, setTools] = useState<Tool[]>([]);
  const [htbStats, setHtbStats] = useState<HTBStats>({
    machinesPwned: 127,
    globalRanking: 15420,
    finalScore: 890,
    htbRank: 'Hacker',
    lastUpdated: new Date().toISOString()
  });

  const [thmStats, setThmStats] = useState<THMStats>({
    thm_rank: 'Beginner',
    rooms_completed: 5,
    streak: 3,
    badges: [],
    last_updated: new Date().toISOString()
  });




const fullText = "Chasing root one box at a time — crafting exploits, decoding patterns, and breathing life into logic. This is the digital dojo where exploits evolve into mastery.";

  const [randomChars, setRandomChars] = useState<string[]>(Array(20).fill(''));

  useEffect(() => {
    setRandomChars(Array.from({ length: 20 }, () => String.fromCharCode(65 + Math.random() * 26)));
  }, []);

  useEffect(() => {
    let index = 0;
    const timer = setInterval(() => {
      if (index < fullText.length) {
        setDisplayText(fullText.slice(0, index + 1));
        index++;
      } else {
        clearInterval(timer);
      }
    }, 50);
    
    return () => clearInterval(timer);
  }, []);

  // Fetch tools from API with caching
  useEffect(() => {
    const fetchTools = async () => {
      try {
        // Check cache first (5 minutes for homepage)
        const cached = localStorage.getItem('homepage_tools');
        const cacheTimestamp = localStorage.getItem('homepage_tools_timestamp');
        const now = Date.now();
        const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
        
        if (cached && cacheTimestamp && (now - parseInt(cacheTimestamp)) < CACHE_DURATION) {
          // Use cached data
          const cachedTools = JSON.parse(cached);
          console.log('Using cached tools:', cachedTools);
          setTools(cachedTools);
          return;
        }
        
        // Fetch fresh data from latest tools and payloads endpoints
        console.log('Fetching fresh tools and payloads data...');
        
        let allTools: Tool[] = [];
        
        // Fetch latest tools
        try {
          const toolsResponse = await fetch('/api/tools/latest?limit=20&fresh=true');
          if (toolsResponse.ok) {
            const toolsData = await toolsResponse.json();
            const latestTools = toolsData.tools || [];
            allTools = [...allTools, ...latestTools];
            console.log('Fetched latest tools:', latestTools.length);
          }
        } catch (error) {
          console.error('Error fetching latest tools:', error);
        }
        
        // Fetch latest payloads
        try {
          const payloadsResponse = await fetch('/api/tools/payloads?limit=20&fresh=true');
          if (payloadsResponse.ok) {
            const payloadsData = await payloadsResponse.json();
            const latestPayloads = (payloadsData.payloads || []).map((payload: any) => ({
              id: payload.id,
              name: payload.name,
              description: payload.description,
              link: undefined, // Payloads don't have external links
              tags: payload.tags || [],
              stars: undefined,
              language: payload.language,
              lastUpdated: payload.lastUpdated || new Date().toISOString()
            }));
            allTools = [...allTools, ...latestPayloads];
            console.log('Fetched latest payloads:', latestPayloads.length);
          }
        } catch (error) {
          console.error('Error fetching latest payloads:', error);
        }
        
        // Remove duplicates by ID and name
        const uniqueTools = allTools.filter((tool, index, self) => 
          index === self.findIndex(t => t.id === tool.id || t.name === tool.name)
        );
        
        // Sort by lastUpdated or publishedAt (newest first), then by stars as fallback
        const sortedTools = uniqueTools.sort((a, b) => {
          const dateA = new Date(a.lastUpdated || a.publishedAt || '1970-01-01').getTime();
          const dateB = new Date(b.lastUpdated || b.publishedAt || '1970-01-01').getTime();
          
          if (dateA !== dateB) {
            return dateB - dateA; // Newest first
          }
          
          // Fallback to stars if dates are the same
          return (b.stars || 0) - (a.stars || 0);
        });
        
        // Get top 3 tools for homepage
        const latestTools = sortedTools.slice(0, 3);
        
        console.log('Final latest tools selected:', latestTools);
        setTools(latestTools);
        
        // Cache the results
        localStorage.setItem('homepage_tools', JSON.stringify(latestTools));
        localStorage.setItem('homepage_tools_timestamp', now.toString());
      } catch (error) {
        console.error('Error fetching tools:', error);
        // Try to use cached data even if expired
        const cached = localStorage.getItem('homepage_tools');
        if (cached) {
          try {
            const cachedTools = JSON.parse(cached);
            console.log('Using expired cached tools due to error:', cachedTools);
            setTools(cachedTools);
          } catch (parseError) {
            console.error('Error parsing cached tools:', parseError);
          }
        }
      }
    };

    fetchTools();
  }, []);

  // Fetch HTB profile stats from D1 database
  useEffect(() => {
    const fetchHTBStats = async () => {
      try {
        // Try D1 API first
        const response = await fetch('/api/admin/htb-stats-d1');
        if (response.ok) {
          const data = await response.json();
          // Convert D1 format to component format
          const statsData = {
            machinesPwned: data.machines_pwned || data.machinesPwned || 127,
            globalRanking: data.global_ranking || data.globalRanking || 15420,
            finalScore: data.final_score || data.finalScore || 890,
            htbRank: data.htb_rank || data.htbRank || 'Hacker',
            lastUpdated: data.last_updated || data.lastUpdated || new Date().toISOString()
          };
          setHtbStats(statsData);
        } else {
          // Fallback to original API
          const fallbackResponse = await fetch('/api/htb-profile');
          if (fallbackResponse.ok) {
            const fallbackData = await fallbackResponse.json();
            setHtbStats(fallbackData);
          }
        }
      } catch (error) {
        console.error('Error fetching HTB stats:', error);
        // Keep default stats if both APIs fail
      }
    };

    fetchHTBStats();
    
    // Refresh HTB stats every 5 minutes
    const interval = setInterval(fetchHTBStats, 5 * 60 * 1000);
    
    return () => clearInterval(interval);
  }, []);

  // Fetch THM profile stats from D1 database
  useEffect(() => {
    const fetchTHMStats = async () => {
      try {
        const response = await fetch('/api/admin/thm-stats-d1');
        if (response.ok) {
          const data = await response.json();
          setThmStats(data);
        }
      } catch (error) {
        console.error('Error fetching THM stats:', error);
        // Keep default stats if API fails
      }
    };

    fetchTHMStats();
    
    // Refresh THM stats every 5 minutes
    const interval = setInterval(fetchTHMStats, 5 * 60 * 1000);
    
    return () => clearInterval(interval);
  }, []);

  // Load machines and get latest completed ones (both HTB and THM)
  useEffect(() => {
    const loadMachines = async () => {
      let machinesList: Machine[] = [];
      
      // Fetch HTB machines
      try {
        const response = await fetch('/api/admin/htb-machines-d1');
        if (response.ok) {
          const apiData = await response.json();
          if (Array.isArray(apiData) && apiData.length > 0) {
            machinesList = apiData.map((machine: any) => ({
              ...machine,
              platform: 'HTB' as const
            }));
          } else {
            // Fallback to static data
            machinesList = machinesData.map((machine: any) => ({
              ...machine,
              platform: 'HTB' as const
            }));
          }
        } else {
          // Fallback to static data
          machinesList = machinesData.map((machine: any) => ({
            ...machine,
            platform: 'HTB' as const
          }));
        }
      } catch (error) {
        console.error('Error fetching HTB machines from API, using static data:', error);
        machinesList = machinesData.map((machine: any) => ({
          ...machine,
          platform: 'HTB' as const
        }));
      }

      // Fetch THM rooms
      try {
        const thmResponse = await fetch('/api/admin/thm-rooms-d1');
        if (thmResponse.ok) {
          const thmData = await thmResponse.json();
          if (Array.isArray(thmData) && thmData.length > 0) {
            // Convert THM rooms to Machine format
            const thmMachines: Machine[] = thmData.map((room: THMRoom) => ({
              id: room.id,
              name: room.title || room.name,
              os: 'Linux', // Default OS for THM rooms
              difficulty: room.difficulty,
              status: room.status,
              dateCompleted: room.dateCompleted || room.date_completed,
              tags: Array.isArray(room.tags) ? room.tags : (room.tags ? room.tags.split(',').map(t => t.trim()) : []),
              writeup: room.writeup,
              platform: 'THM' as const
            }));
            
            // Merge THM rooms with HTB machines
            machinesList = [...machinesList, ...thmMachines];
          }
        }
      } catch (error) {
        console.error('Error fetching THM rooms:', error);
      }
      
      // Also check localStorage for any additional HTB machines
      const savedMachines = localStorage.getItem('htb-machines');
      if (savedMachines) {
        try {
          const localMachines = JSON.parse(savedMachines);
          if (Array.isArray(localMachines) && localMachines.length > 0) {
            // Merge with API/static data, preferring local data for existing IDs
            const mergedMachines = [...machinesList];
            localMachines.forEach(localMachine => {
              const existingIndex = mergedMachines.findIndex(m => m.id === localMachine.id);
              if (existingIndex >= 0) {
                mergedMachines[existingIndex] = {
                  ...localMachine,
                  platform: 'HTB' as const
                };
              } else {
                mergedMachines.push({
                  ...localMachine,
                  platform: 'HTB' as const
                });
              }
            });
            machinesList = mergedMachines;
          }
        } catch (error) {
          console.error('Error parsing saved machines:', error);
        }
      }
      
      setMachines(machinesList);
      
      // Fetch CTF writeups
      try {
        const ctfResponse = await fetch('/api/admin/ctf-writeups-d1');
        if (ctfResponse.ok) {
          const ctfData = await ctfResponse.json();
          if (Array.isArray(ctfData) && ctfData.length > 0) {
            setCTFWriteups(ctfData.map((writeup: any) => ({
              ...writeup,
              platform: 'CTF' as const
            })));
          }
        }
      } catch (error) {
        console.error('Error fetching CTF writeups:', error);
      }
      
      // Combine all writeups (machines + CTF) and get latest 3 completed
      const allWriteups: WriteupItem[] = [
        ...machinesList.filter(machine => machine.status === 'Completed' && machine.dateCompleted),
        ...ctfWriteups.filter(writeup => writeup.status === 'Completed' && writeup.dateCompleted)
      ];
      
      const latestWriteups = allWriteups
        .sort((a, b) => {
          const dateA = a.dateCompleted || '';
          const dateB = b.dateCompleted || '';
          return new Date(dateB).getTime() - new Date(dateA).getTime();
        })
        .slice(0, 3);
      
      console.log('Latest completed writeups (HTB + THM + CTF):', latestWriteups);
      setLatestMachines(latestWriteups);
    };

    loadMachines();
    
    // Listen for storage changes to update when machines are modified
    const handleStorageChange = () => {
      loadMachines();
    };
    
    window.addEventListener('storage', handleStorageChange);
    
    // Check periodically for updates (reduced frequency)
    const interval = setInterval(loadMachines, 30000); // Every 30 seconds
    
    return () => {
      window.removeEventListener('storage', handleStorageChange);
      clearInterval(interval);
    };
  }, [ctfWriteups]);

  const getTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInMs = now.getTime() - date.getTime();
    const diffInDays = Math.floor(diffInMs / (1000 * 60 * 60 * 24));
    
    if (diffInDays === 0) return 'Today';
    if (diffInDays === 1) return '1 day ago';
    if (diffInDays < 7) return `${diffInDays} days ago`;
    if (diffInDays < 30) return `${Math.floor(diffInDays / 7)} weeks ago`;
    return `${Math.floor(diffInDays / 30)} months ago`;
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty.toLowerCase()) {
      case 'easy':
        return 'border-cyber-green';
      case 'medium':
        return 'border-cyber-blue';
      case 'hard':
        return 'border-cyber-pink';
      default:
        return 'border-cyber-purple';
    }
  };



  return (
    <Layout>
      {/* Hero Section */}
      <section className="text-center py-8 sm:py-12 lg:py-16 xl:py-20 relative px-4">

        {/* Minimal glass container for hero content */}
        <div className="relative z-10 max-w-4xl mx-auto rounded-2xl backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-5 sm:p-8">
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl xl:text-8xl mb-3 sm:mb-4 lg:mb-6 tracking-wider">
            <span
              className="block hero-title"
              style={{
                fontFamily: 'var(--font-righteous), sans-serif',
                textTransform: 'none',
                backgroundImage: 'linear-gradient(90deg, #00ff41 0%, #ff0080 50%, #ffb300 100%)',
                backgroundSize: '220% 100%',
                WebkitBackgroundClip: 'text',
                color: 'transparent',
                animation: 'gradientShift 7s ease-in-out infinite',
              }}
            >
              0xJerry
            </span>
          </h1>
          
          <div className="text-sm sm:text-base md:text-lg lg:text-xl xl:text-2xl mb-6 sm:mb-8 min-h-[3rem] sm:min-h-[4rem] lg:min-h-[5rem] xl:min-h-[6rem] px-2 sm:px-4 lg:px-8 text-foreground">
            <span className="terminal-cursor inline-block leading-relaxed break-words">{displayText}</span>
          </div>
          
          <div className="flex flex-col sm:flex-row justify-center items-center space-y-2 sm:space-y-0 sm:space-x-3 lg:space-x-6 xl:space-x-8 mb-6 sm:mb-8 lg:mb-12">
            <div className="flex items-center space-x-2 text-cyber-blue text-xs sm:text-sm lg:text-base">
              <FaSkull className="animate-pulse flex-shrink-0" />
              <span>Penetration Testing</span>
            </div>
            <div className="flex items-center space-x-2 text-cyber-purple text-xs sm:text-sm lg:text-base">
              <FaBug className="animate-pulse flex-shrink-0" />
              <span>Bug Hunting</span>
            </div>
            <div className="flex items-center space-x-2 text-cyber-pink text-xs sm:text-sm lg:text-base">
              <FaShieldAlt className="animate-pulse flex-shrink-0" />
              <span>Red Teaming</span>
            </div>
          </div>
          
          <div className="flex flex-col sm:flex-row justify-center space-y-3 sm:space-y-0 sm:space-x-4 lg:space-x-6">
            <Link 
              href="/machines" 
              className="border-2 border-cyber-green/60 text-cyber-green px-4 sm:px-6 lg:px-8 py-2 sm:py-3 lg:py-4 rounded-lg font-bold hover:bg-cyber-green hover:text-black transition-all duration-300 hover:shadow-[0_0_24px_rgba(0,255,65,0.6)] transform hover:scale-105 text-sm sm:text-base backdrop-blur-sm bg-black/20"
            >
              View Writeups
            </Link>
            <Link 
              href="/about" 
              className="border border-cyber-green/50 text-cyber-green px-4 sm:px-6 lg:px-8 py-2 sm:py-3 lg:py-4 rounded-lg font-bold hover:bg-cyber-green hover:text-black transition-all duration-300 text-sm sm:text-base backdrop-blur-sm bg-black/20"
            >
              Learn More
            </Link>
          </div>
        </div>
      </section>
      

      {/* Stats Dashboard */}
      <section className="py-8 sm:py-12 lg:py-16 px-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4 lg:gap-6 max-w-4xl mx-auto">
          <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4 lg:p-6 transition-all duration-300 group">
            <div className="flex items-center justify-between mb-2 sm:mb-3 lg:mb-4">
              <FaShieldAlt className="text-lg sm:text-xl lg:text-2xl text-cyber-blue group-hover:animate-pulse flex-shrink-0" />
              <span className="text-2xl font-bold text-cyber-blue">{htbStats.htbRank}</span>
            </div>
            <h3 className="text-xs sm:text-sm lg:text-base font-semibold mb-1 lg:mb-2">HTB Rank</h3>
            <p className="text-xs text-gray-400">Current tier level</p>
          </div>
          
          <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4 lg:p-6 transition-all duration-300 group">
            <div className="flex items-center justify-between mb-2 sm:mb-3 lg:mb-4">
              <FaShieldAlt className="text-lg sm:text-xl lg:text-2xl text-cyber-purple group-hover:animate-pulse flex-shrink-0" />
              <span className="text-2xl font-bold text-cyber-purple">{thmStats.thm_rank}</span>
            </div>
            <h3 className="text-xs sm:text-sm lg:text-base font-semibold mb-1 lg:mb-2">THM Level</h3>
            <p className="text-xs text-gray-400">Current rank</p>
          </div>
        </div>

        {/* THM Badges Section */}
        {thmStats.badges && thmStats.badges.length > 0 && (
          <div className="mt-6 sm:mt-8 max-w-7xl mx-auto">
            <h3 className="text-lg sm:text-xl font-bold mb-3 sm:mb-4 text-cyber-purple text-center">TryHackMe Badges</h3>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
              {thmStats.badges.slice(0, 4).map((badge, index) => (
                <div key={index} className="bg-card-bg border border-cyber-purple/30 p-3 sm:p-4 rounded-lg text-center hover:border-cyber-purple transition-all duration-300">
                  <div className="text-xl sm:text-2xl mb-2">{badge.icon}</div>
                  <h4 className="font-semibold text-cyber-purple text-xs sm:text-sm mb-1">{badge.name}</h4>
                  <p className="text-xs text-gray-400 leading-tight">{badge.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
      
      {/* Recent Activity */}
      <section className="py-12 md:py-16 px-4">
        <h2 className="text-2xl md:text-3xl font-cyber font-bold mb-6 md:mb-8 text-center">
          <span data-text="Recent Activity">
            Recent Activity
          </span>
        </h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 md:gap-8 max-w-7xl mx-auto">
          {/* Latest Writeups */}
          <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-4 md:p-6">
            <h3 className="text-lg md:text-xl font-bold mb-3 md:mb-4 text-cyber-green">Latest Writeups</h3>
            <div className="space-y-3 md:space-y-4">
              {latestMachines.length > 0 ? (
                latestMachines.map(item => {
                  const isCTF = 'ctfName' in item;
                  const isHTB = !isCTF && item.platform === 'HTB';
                  const isTHM = !isCTF && item.platform === 'THM';
                  
                  return (
                    <div 
                      key={item.id} 
                      className={`border-l-4 ${getDifficultyColor(item.difficulty)} pl-3 md:pl-4 transition-all duration-300 hover:bg-cyber-green/10 py-2`}
                    >
                      <Link href={
                        isCTF ? `/ctf/${(item as CTFWriteup).slug}` :
                        isTHM ? `/machines/thm/${item.id}` : 
                        `/machines/htb/${item.id}`
                      }>
                        <div className="flex items-center justify-between mb-1">
                          <h4 className="font-semibold hover:text-cyber-blue cursor-pointer text-sm md:text-base break-words flex items-center gap-2">
                            {isCTF ? (item as CTFWriteup).title : item.name}
                            <span className={`text-xs px-2 py-1 rounded-full font-bold ${
                              isCTF ? 'bg-cyber-pink/20 text-cyber-pink' :
                              isHTB ? 'bg-cyber-blue/20 text-cyber-blue' : 
                              'bg-cyber-purple/20 text-cyber-purple'
                            }`}>
                              {isCTF ? 'CTF' : item.platform}
                            </span>
                          </h4>
                        </div>
                      </Link>
                      <p className="text-xs md:text-sm text-gray-400 mb-1 md:mb-2">
                        {isCTF 
                          ? `${(item as CTFWriteup).ctfName} | ${(item as CTFWriteup).category}` 
                          : isHTB ? item.os : 'TryHackMe'
                        } | {item.difficulty} | {item.dateCompleted ? getTimeAgo(item.dateCompleted) : 'N/A'}
                      </p>
                      {item.tags && (
                        <div className="flex flex-wrap gap-1">
                          {(Array.isArray(item.tags) ? item.tags : [item.tags]).slice(0, 3).map((tag, index) => (
                            <span key={index} className={`text-xs px-2 py-1 rounded whitespace-nowrap ${
                              isCTF ? 'bg-cyber-pink/20 text-cyber-pink' :
                              isHTB ? 'bg-cyber-blue/20 text-cyber-blue' : 
                              'bg-cyber-purple/20 text-cyber-purple'
                            }`}>
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-4">
                  <p className="text-gray-400 mb-2 text-sm md:text-base">No completed machines yet.</p>
                  <Link href="/machines" className="text-cyber-blue hover:text-cyber-green transition-colors text-sm md:text-base">
                    Start hacking →
                  </Link>
                </div>
              )}
            </div>
            <div className="mt-3 md:mt-4 pt-3 md:pt-4 border-t border-cyber-green/30">
              <Link href="/machines" className="text-cyber-blue hover:text-cyber-green transition-colors text-xs md:text-sm">
                View all writeups →
              </Link>
            </div>
          </div>
          
{/* Tools & Exploits */}
          <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-4 md:p-6">
            <div className="flex items-center justify-between mb-3 md:mb-4">
              <h3 className="text-lg md:text-xl font-bold text-cyber-green">Latest Tools & Payloads</h3>
              <button
                onClick={() => {
                  // Clear cache and refetch
                  localStorage.removeItem('homepage_tools');
                  localStorage.removeItem('homepage_tools_timestamp');
                  window.location.reload();
                }}
                className="text-cyber-blue hover:text-cyber-green transition-colors text-sm flex items-center space-x-1"
                title="Refresh tools"
              >
                <FaCode />
                <span>Refresh</span>
              </button>
            </div>
            <div className="space-y-3 md:space-y-4">
              {tools.length > 0 ? (
                tools.map((tool: Tool) => (
                  <div key={tool.id} className="border-l-4 border-cyber-purple pl-3 md:pl-4 hover:bg-cyber-green/10 transition-all duration-300">
                    {tool.link ? (
                      <Link href={tool.link} target="_blank" rel="noopener noreferrer">
                        <h4 className="font-semibold hover:text-cyber-blue cursor-pointer flex items-center gap-2 text-sm md:text-base break-words">
                          <span className="break-all">{tool.name}</span>
                          {tool.stars && <span className="text-xs text-yellow-400 whitespace-nowrap">⭐ {tool.stars}</span>}
                          {(tool.lastUpdated || tool.publishedAt) && (
                            <span className="text-xs text-cyber-green whitespace-nowrap">
                              🕒 {new Date(tool.lastUpdated || tool.publishedAt!).toLocaleDateString()}
                            </span>
                          )}
                        </h4>
                      </Link>
                    ) : (
                      <div>
                        <h4 className="font-semibold text-sm md:text-base break-words flex items-center gap-2">
                          <span className="break-all">{tool.name}</span>
                          <span className="text-xs px-2 py-1 bg-cyber-purple/20 text-cyber-purple rounded">PAYLOAD</span>
                          {(tool.lastUpdated || tool.publishedAt) && (
                            <span className="text-xs text-cyber-green whitespace-nowrap">
                              🕒 {new Date(tool.lastUpdated || tool.publishedAt!).toLocaleDateString()}
                            </span>
                          )}
                        </h4>
                      </div>
                    )}
                    <p className="text-xs md:text-sm text-gray-400 mb-1 md:mb-2 leading-relaxed line-clamp-2">{tool.description}</p>
                    {tool.tags && tool.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {tool.tags.slice(0, 3).map((tag, index) => (
                          <span key={index} className="text-xs px-2 py-1 bg-cyber-green/20 text-cyber-green rounded whitespace-nowrap">
                            {tag}
                          </span>
                        ))}
                        {tool.tags.length > 3 && (
                          <span className="text-xs px-2 py-1 bg-gray-500/20 text-gray-400 rounded">
                            +{tool.tags.length - 3} more
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center py-4">
                  <p className="text-gray-400 mb-2 text-sm md:text-base">Loading latest tools and payloads...</p>
                  <Link href="/tools" className="text-cyber-blue hover:text-cyber-green transition-colors text-sm md:text-base">
                    View all tools →
                  </Link>
                </div>
              )}
            </div>
            <div className="mt-3 md:mt-4 pt-3 md:pt-4 border-t border-cyber-green/30">
              <Link href="/tools" className="text-cyber-blue hover:text-cyber-green transition-colors text-xs md:text-sm">
                View all tools & payloads →
              </Link>
            </div>
          </div>
        </div>
      </section>
      
      {/* Community Spotlight */}
      <section className="py-8 sm:py-12 px-4">
        <h2 className="text-2xl md:text-3xl font-cyber font-bold mb-6 text-center">
          <span data-text="Community Spotlight">
            Community Spotlight
          </span>
        </h2>
        
        <div className="max-w-4xl mx-auto">
          <SubscriberSpotlight 
            type="latest" 
            title="Latest Subscribers" 
          />
        </div>
      </section>
    </Layout>
  );
}
