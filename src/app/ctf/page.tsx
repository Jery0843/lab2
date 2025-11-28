'use client';

import { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import { FaFilter, FaSearch, FaSync, FaTrophy, FaFlag } from 'react-icons/fa';

interface CTFWriteup {
  id: string;
  title: string;
  slug: string;
  ctfName: string;
  category: string;
  difficulty: string;
  points: number;
  status: string;
  isActive?: boolean;
  dateCompleted: string | null;
  tags: string[];
  writeup: string | null;
  summary: string | null;
  flag?: string;
}

const CTFWriteups = () => {
  const [writeups, setWriteups] = useState<CTFWriteup[]>([]);
  const [filteredWriteups, setFilteredWriteups] = useState<CTFWriteup[]>([]);

  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState('All');
  const [filterDifficulty, setFilterDifficulty] = useState('All');
  const [filterStatus, setFilterStatus] = useState('All');
  const [filterCTF, setFilterCTF] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch writeups from D1 database
  const fetchWriteups = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/admin/ctf-writeups-d1');
      const data = await response.json();
      
      if (response.ok) {
        const writeupsArray = Array.isArray(data) ? data : (data.writeups || []);
        setWriteups(writeupsArray);
      } else {
        console.warn('D1 API not available, using fallback data:', data.error);
        setWriteups([]);
        setError('Using cached data - database temporarily unavailable');
      }
    } catch (error) {
      console.error('Error fetching writeups:', error);
      setWriteups([]);
      setError('Failed to load writeups from database');
    } finally {
      setLoading(false);
    }
  };

  // Load writeups data on component mount
  useEffect(() => {
    fetchWriteups();
  }, []);

  useEffect(() => {
    let filtered = writeups;

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(writeup =>
        writeup.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        writeup.ctfName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        writeup.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }

    // Category filter
    if (filterCategory !== 'All') {
      filtered = filtered.filter(writeup => writeup.category === filterCategory);
    }

    // Difficulty filter
    if (filterDifficulty !== 'All') {
      filtered = filtered.filter(writeup => writeup.difficulty === filterDifficulty);
    }

    // Status filter
    if (filterStatus !== 'All') {
      filtered = filtered.filter(writeup => writeup.status === filterStatus);
    }

    // CTF filter
    if (filterCTF !== 'All') {
      filtered = filtered.filter(writeup => writeup.ctfName === filterCTF);
    }

    setFilteredWriteups(filtered);
  }, [writeups, searchTerm, filterCategory, filterDifficulty, filterStatus, filterCTF]);

  const handleViewWriteup = (writeup: CTFWriteup) => {
    window.location.href = `/ctf/${writeup.slug}`;
  };

  const stats = {
    total: writeups.length,
    completed: writeups.filter(w => w.status === 'Completed').length,
    inProgress: writeups.filter(w => w.status === 'In Progress').length,
    easy: writeups.filter(w => w.difficulty === 'Easy').length,
    medium: writeups.filter(w => w.difficulty === 'Medium').length,
    hard: writeups.filter(w => w.difficulty === 'Hard').length,
    totalPoints: writeups.filter(w => w.status === 'Completed').reduce((sum, w) => sum + w.points, 0)
  };

  // Get unique values for filters
  const categories = [...new Set(writeups.map(w => w.category))];
  const ctfNames = [...new Set(writeups.map(w => w.ctfName))];

  return (
    <Layout>
      <div className="py-8">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-4xl font-cyber font-bold" data-text="CTF Writeups">
              CTF Writeups
            </h1>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={fetchWriteups}
              disabled={loading}
              className="bg-cyber-blue text-white px-4 py-3 rounded-lg font-bold hover:bg-cyber-purple transition-colors flex items-center space-x-2 border-2 border-cyber-blue"
            >
              <FaSync className={loading ? 'animate-spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Error/Success Banner */}
        {error && (
          <div className={`mb-6 p-4 rounded-lg border ${error.includes('✅') ? 'bg-green-900/20 border-green-500/50 text-green-400' : 'bg-red-900/20 border-red-500/50 text-red-400'}`}>
            <div className="flex items-center justify-between">
              <span>{error}</span>
              <button 
                onClick={() => setError(null)}
                className="text-gray-400 hover:text-white"
              >
                ×
              </button>
            </div>
          </div>
        )}

        {/* Loading Indicator */}
        {loading && (
          <div className="mb-6 p-4 rounded-lg bg-cyber-blue/20 border border-cyber-blue/50 text-cyber-blue">
            <div className="flex items-center space-x-2">
              <FaSync className="animate-spin" />
              <span>Loading writeups from database...</span>
            </div>
          </div>
        )}

        {/* Stats Dashboard */}
        <div className="grid grid-cols-2 md:grid-cols-7 gap-4 mb-8">
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-cyber-green">{stats.total}</div>
            <div className="text-sm text-gray-400">Total</div>
          </div>
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{stats.completed}</div>
            <div className="text-sm text-gray-400">Completed</div>
          </div>
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-yellow-400">{stats.inProgress}</div>
            <div className="text-sm text-gray-400">In Progress</div>
          </div>
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{stats.easy}</div>
            <div className="text-sm text-gray-400">Easy</div>
          </div>
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-yellow-400">{stats.medium}</div>
            <div className="text-sm text-gray-400">Medium</div>
          </div>
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-red-400">{stats.hard}</div>
            <div className="text-sm text-gray-400">Hard</div>
          </div>
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-cyber-purple">{stats.totalPoints}</div>
            <div className="text-sm text-gray-400">Points</div>
          </div>
        </div>

        {/* Filters */}
        <div className="glass-panel p-6 rounded-lg mb-8">
          <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
            {/* Search */}
            <div className="relative">
              <FaSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyber-green" />
              <input
                type="text"
                placeholder="Search writeups..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-terminal-bg border border-cyber-green/50 pl-10 pr-4 py-2 rounded text-cyber-green focus:border-cyber-green focus:outline-none"
              />
            </div>

            {/* Category Filter */}
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="bg-terminal-bg border border-cyber-green/50 px-4 py-2 rounded text-cyber-green focus:border-cyber-green focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
            >
              <option value="All">All Categories</option>
              {categories.map(category => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>

            {/* Difficulty Filter */}
            <select
              value={filterDifficulty}
              onChange={(e) => setFilterDifficulty(e.target.value)}
              className="bg-terminal-bg border border-cyber-green/50 px-4 py-2 rounded text-cyber-green focus:border-cyber-green focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
            >
              <option value="All">All Difficulties</option>
              <option value="Easy">Easy</option>
              <option value="Medium">Medium</option>
              <option value="Hard">Hard</option>
              <option value="Insane">Insane</option>
            </select>

            {/* Status Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-terminal-bg border border-cyber-green/50 px-4 py-2 rounded text-cyber-green focus:border-cyber-green focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
            >
              <option value="All">All Statuses</option>
              <option value="Completed">Completed</option>
              <option value="In Progress">In Progress</option>
            </select>

            {/* CTF Filter */}
            <select
              value={filterCTF}
              onChange={(e) => setFilterCTF(e.target.value)}
              className="bg-terminal-bg border border-cyber-green/50 px-4 py-2 rounded text-cyber-green focus:border-cyber-green focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
            >
              <option value="All">All CTFs</option>
              {ctfNames.map(ctf => (
                <option key={ctf} value={ctf}>{ctf}</option>
              ))}
            </select>

            {/* Clear Filters */}
            <button
              onClick={() => {
                setSearchTerm('');
                setFilterCategory('All');
                setFilterDifficulty('All');
                setFilterStatus('All');
                setFilterCTF('All');
              }}
              className="bg-cyber-green text-black px-4 py-2 rounded font-bold hover:bg-cyber-blue transition-colors"
            >
              Clear All
            </button>
          </div>
        </div>

        {/* Writeups Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredWriteups.map((writeup) => (
            <div key={writeup.id} className="rounded-2xl backdrop-blur-sm bg-black/40 light:bg-white/60 border border-cyber-green/30 p-6 hover:border-cyber-green transition-all cursor-pointer"
                 onClick={() => handleViewWriteup(writeup)}>
              <div className="flex justify-between items-start mb-4">
                <h3 className="text-xl font-bold text-cyber-green mb-2">{writeup.title}</h3>
                <div className="flex items-center space-x-2">
                  {writeup.points > 0 && (
                    <span className="flex items-center text-cyber-purple text-sm">
                      <FaTrophy className="mr-1" />
                      {writeup.points}
                    </span>
                  )}
                  {writeup.status === 'Completed' && (
                    <FaFlag className="text-green-400" />
                  )}
                </div>
              </div>
              
              <div className="mb-3">
                <span className="text-sm text-gray-400">{writeup.ctfName}</span>
              </div>
              
              <div className="flex items-center space-x-4 mb-3">
                <span className="px-3 py-1 bg-cyber-blue/20 text-cyber-blue rounded-full text-sm font-semibold">{writeup.category}</span>
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  writeup.difficulty === 'Easy' ? 'bg-green-500/20 text-green-400' :
                  writeup.difficulty === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                  writeup.difficulty === 'Hard' ? 'bg-red-500/20 text-red-400' :
                  'bg-purple-500/20 text-purple-400'
                }`}>{writeup.difficulty}</span>
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  writeup.status === 'Completed' ? 'bg-green-500/20 text-green-400 border border-green-400' :
                  'bg-yellow-500/20 text-yellow-400 border border-yellow-400'
                }`}>{writeup.status}</span>
              </div>
              
              {writeup.summary && (
                <p className="text-gray-300 text-sm mb-4 line-clamp-2">{writeup.summary}</p>
              )}
              
              <div className="flex flex-wrap gap-2">
                {writeup.tags.slice(0, 3).map((tag, index) => (
                  <span key={index} className="px-2 py-1 bg-cyber-green/10 text-cyber-green text-xs rounded border border-cyber-green/30">
                    {tag}
                  </span>
                ))}
                {writeup.tags.length > 3 && (
                  <span className="px-2 py-1 bg-gray-500/20 text-gray-400 text-xs rounded">
                    +{writeup.tags.length - 3} more
                  </span>
                )}
              </div>
              
              {writeup.dateCompleted && (
                <div className="mt-4 text-xs text-gray-500">
                  Completed: {new Date(writeup.dateCompleted).toLocaleDateString()}
                </div>
              )}
            </div>
          ))}
        </div>

        {filteredWriteups.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-400 text-lg">No writeups found matching your criteria.</p>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default CTFWriteups;