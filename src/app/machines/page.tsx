'use client';

import { useState, useEffect } from 'react';
import { Metadata } from 'next';
import Link from 'next/link';
import { FaServer, FaChartLine, FaTrophy, FaCode } from 'react-icons/fa';

// Note: Metadata export moved to layout.tsx for client components

interface HTBStats {
  rank: number;
  points: number;
  owns_user: number;
  owns_root: number;
  owns_total: number;
  respect: number;
  university_rank: number | null;
}

interface THMStats {
  rank: number;
  points: number;
  rooms_completed: number;
  streak: number;
  badges: string[];
  learning_paths_completed: number;
}

export default function MachinesPage() {
  const [htbStats, setHtbStats] = useState<HTBStats>({
    rank: 15234,
    points: 1337,
    owns_user: 42,
    owns_root: 38,
    owns_total: 80,
    respect: 15,
    university_rank: null
  });

  const [thmStats, setThmStats] = useState<THMStats>({
    rank: 8456,
    points: 2895,
    rooms_completed: 67,
    streak: 12,
    badges: ['Top 1%', 'Pwned', 'OSCP Prep'],
    learning_paths_completed: 3
  });





  useEffect(() => {
    // Fetch HTB stats
    const fetchHTBStats = async () => {
      try {
        const response = await fetch('/api/admin/htb-stats-d1');
        if (response.ok) {
          const data = await response.json();
          const stats = {
            rank: data.globalRanking || 15234,
            points: data.finalScore || 1337,
            owns_user: data.machinesPwned || 42,
            owns_root: data.machinesPwned || 42, // Same as user owns
            owns_total: data.machinesPwned || 80,
            respect: 15,
            university_rank: null
          };
          setHtbStats(stats);
        }
      } catch (error) {
        console.error('Error fetching HTB stats:', error);
        // Set fallback data on error
        const fallbackStats = {
          rank: 15234,
          points: 1337,
          owns_user: 42,
          owns_root: 38,
          owns_total: 80,
          respect: 15,
          university_rank: null
        };
        setHtbStats(fallbackStats);
      }
    };

    // Fetch THM stats
    const fetchTHMStats = async () => {
      try {
        const response = await fetch('/api/admin/thm-stats-d1');
        if (response.ok) {
          const data = await response.json();
          const stats = {
            rank: data.global_ranking || 8456,
            points: data.total_points || 2895,
            rooms_completed: data.rooms_completed || 67,
            streak: data.streak || 12,
            badges: data.badges || ['Top 1%', 'Pwned', 'OSCP Prep'],
            learning_paths_completed: 3
          };
          setThmStats(stats);
        }
      } catch (error) {
        console.error('Error fetching THM stats:', error);
        // Set fallback data on error
        const fallbackStats = {
          rank: 8456,
          points: 2895,
          rooms_completed: 67,
          streak: 12,
          badges: ['Top 1%', 'Pwned', 'OSCP Prep'],
          learning_paths_completed: 3
        };
        setThmStats(fallbackStats);
      }
    };

    fetchHTBStats();
    fetchTHMStats();
  }, []);



  return (
    <div className="min-h-screen">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 lg:py-12">


        {/* Header */}
        <div className="text-center mb-8 sm:mb-10 lg:mb-12 px-2 sm:px-4">
          <div className="relative z-10 max-w-4xl mx-auto rounded-2xl backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-5 sm:p-8">
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-cyber font-bold mb-3 sm:mb-4">
              <span
                className="block"
                style={{
                  backgroundImage: 'linear-gradient(90deg, #00ff41, #ff0080, #ffb300)',
                  backgroundSize: '200% 100%',
                  WebkitBackgroundClip: 'text',
                  color: 'transparent',
                  animation: 'gradientShift 6s ease-in-out infinite',
                }}
                data-text="MACHINE LABS"
              >
                MACHINE LABS
              </span>
            </h1>
            <div className="flex justify-center">
              <p className="text-base sm:text-lg lg:text-xl text-center text-foreground max-w-3xl mx-auto leading-relaxed">
                Cybersecurity training platforms with hands-on machine exploitation and detailed writeups.
              </p>
            </div>
          </div>
        </div>

        {/* Platform Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-8 max-w-7xl mx-auto items-start">
          {/* Hack The Box Card */}
          <Link href="/machines/htb" className="block group">
            <div className="glass-panel rounded-lg p-4 sm:p-6 lg:p-8 transition-all duration-300">
              <div className="flex items-center mb-4 sm:mb-6">
                <div className="w-12 h-12 sm:w-14 sm:h-14 lg:w-16 lg:h-16 bg-cyber-green/20 rounded-lg flex items-center justify-center mr-3 sm:mr-4 group-hover:bg-cyber-green/30">
                  <FaServer className="text-2xl sm:text-2xl lg:text-3xl text-cyber-green group-hover:animate-pulse" />
                </div>
                <div>
                  <h2 className="text-lg sm:text-xl lg:text-2xl font-bold text-cyber-green dark:text-cyber-green light:text-green-600 mb-1">Hack The Box</h2>
                  <p className="text-gray-400 dark:text-gray-400 light:text-gray-600 text-sm sm:text-base">Realistic penetration testing labs</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 sm:gap-4 mb-4 sm:mb-6">
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaChartLine className="text-cyber-green dark:text-cyber-green light:text-green-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Global Rank</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-green dark:text-cyber-green light:text-green-600">#{htbStats.rank?.toLocaleString()}</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaTrophy className="text-cyber-green dark:text-cyber-green light:text-green-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Final Score</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-green dark:text-cyber-green light:text-green-600">{htbStats.points?.toLocaleString()}</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaCode className="text-cyber-green dark:text-cyber-green light:text-green-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">User Owns</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-green dark:text-cyber-green light:text-green-600">{htbStats.owns_user}</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaServer className="text-cyber-green dark:text-cyber-green light:text-green-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Root Owns</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-green dark:text-cyber-green light:text-green-600">{htbStats.owns_root}</p>
                </div>
              </div>

              <div className="text-center">
                <span className="inline-flex items-center px-4 sm:px-6 py-2 sm:py-3 rounded-lg text-cyber-green border border-white/5 backdrop-blur-sm bg-black/10 light:bg-white/20 group-hover:bg-cyber-green group-hover:text-black transition-all duration-300 text-sm sm:text-base">
                  Explore HTB Machines →
                </span>
              </div>
            </div>
          </Link>

          {/* TryHackMe Card */}
          <Link href="/machines/thm" className="block group">
            <div className="glass-panel rounded-lg p-4 sm:p-6 lg:p-8 transition-all duration-300">
              <div className="flex items-center mb-4 sm:mb-6">
                <div className="w-12 h-12 sm:w-14 sm:h-14 lg:w-16 lg:h-16 bg-purple-500/20 rounded-lg flex items-center justify-center mr-3 sm:mr-4 group-hover:bg-purple-500/30">
                  <FaServer className="text-2xl sm:text-2xl lg:text-3xl text-purple-500 group-hover:animate-pulse" />
                </div>
                <div>
                  <h2 className="text-lg sm:text-xl lg:text-2xl font-bold text-purple-500 dark:text-purple-400 light:text-purple-600 mb-1">TryHackMe</h2>
                  <p className="text-gray-400 dark:text-gray-400 light:text-gray-600 text-sm sm:text-base">Guided cybersecurity learning</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 sm:gap-4 mb-4 sm:mb-6">
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaChartLine className="text-purple-500 dark:text-purple-400 light:text-purple-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Global Rank</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-purple-500 dark:text-purple-400 light:text-purple-600">#{thmStats.rank?.toLocaleString()}</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaTrophy className="text-purple-500 dark:text-purple-400 light:text-purple-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Badges</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-purple-500 dark:text-purple-400 light:text-purple-600">{thmStats.points?.toLocaleString()}</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaCode className="text-purple-500 dark:text-purple-400 light:text-purple-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Rooms</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-purple-500 dark:text-purple-400 light:text-purple-600">{thmStats.rooms_completed}</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaServer className="text-purple-500 dark:text-purple-400 light:text-purple-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Streak</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-purple-500 dark:text-purple-400 light:text-purple-600">{thmStats.streak} days</p>
                </div>
              </div>

              <div className="text-center">
                <span className="inline-flex items-center px-4 sm:px-6 py-2 sm:py-3 rounded-lg text-purple-500 border border-white/5 backdrop-blur-sm bg-black/10 light:bg-white/20 group-hover:bg-purple-500 group-hover:text-white transition-all duration-300 text-sm sm:text-base">
                  Explore THM Rooms →
                </span>
              </div>
            </div>
          </Link>

          {/* CTF Writeups Card */}
          <Link href="/ctf" className="block group">
            <div className="glass-panel rounded-lg p-4 sm:p-6 lg:p-8 transition-all duration-300">
              <div className="flex items-center mb-4 sm:mb-6">
                <div className="w-12 h-12 sm:w-14 sm:h-14 lg:w-16 lg:h-16 bg-cyber-blue/20 rounded-lg flex items-center justify-center mr-3 sm:mr-4 group-hover:bg-cyber-blue/30">
                  <FaTrophy className="text-2xl sm:text-2xl lg:text-3xl text-cyber-blue group-hover:animate-pulse" />
                </div>
                <div>
                  <h2 className="text-lg sm:text-xl lg:text-2xl font-bold text-cyber-blue dark:text-cyber-blue light:text-blue-600 mb-1">CTF Writeups</h2>
                  <p className="text-gray-400 dark:text-gray-400 light:text-gray-600 text-sm sm:text-base">Capture The Flag challenges</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 sm:gap-4 mb-4 sm:mb-6">
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaCode className="text-cyber-blue dark:text-cyber-blue light:text-blue-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Categories</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-blue dark:text-cyber-blue light:text-blue-600">All</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaChartLine className="text-cyber-blue dark:text-cyber-blue light:text-blue-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Difficulty</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-blue dark:text-cyber-blue light:text-blue-600">Easy - Hard</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaTrophy className="text-cyber-blue dark:text-cyber-blue light:text-blue-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Writeups</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-blue dark:text-cyber-blue light:text-blue-600">Active</p>
                </div>
                <div className="rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-3 sm:p-4">
                  <div className="flex items-center mb-2">
                    <FaServer className="text-cyber-blue dark:text-cyber-blue light:text-blue-600 mr-2 text-sm sm:text-base" />
                    <span className="text-xs sm:text-sm text-gray-400 dark:text-gray-400 light:text-gray-600">Platforms</span>
                  </div>
                  <p className="text-base sm:text-lg lg:text-xl font-bold text-cyber-blue dark:text-cyber-blue light:text-blue-600">Multiple</p>
                </div>
              </div>

              <div className="text-center">
                <span className="inline-flex items-center px-4 sm:px-6 py-2 sm:py-3 rounded-lg text-cyber-blue border border-white/5 backdrop-blur-sm bg-black/10 light:bg-white/20 group-hover:bg-cyber-blue group-hover:text-white transition-all duration-300 text-sm sm:text-base">
                  Explore CTF Writeups →
                </span>
              </div>
            </div>
          </Link>
        </div>
      </div>
    </div>
  );
}
