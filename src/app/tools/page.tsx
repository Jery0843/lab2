'use client';

import { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import { FaGithub, FaCode, FaFileAlt, FaCopy, FaExternalLinkAlt, FaFilter, FaSpinner, FaSync, FaStar, FaExclamationTriangle } from 'react-icons/fa';

// Force dynamic rendering to prevent static prerendering
export const dynamic = 'force-dynamic';

interface Tool {
  id: string;
  name: string;
  description: string;
  link?: string;
  code?: string;
  type?: string;
  tags: string[];
  source?: string;
  stars?: number;
  language?: string;
  publishedAt?: string;
  category?: string;
}

const Tools = () => {
  const [tools, setTools] = useState<Tool[]>([]);
  const [filteredTools, setFilteredTools] = useState<Tool[]>([]);
  const [selectedTag, setSelectedTag] = useState('All');
  const [selectedCategory, setSelectedCategory] = useState<'All' | string>('All');
  const [selectedType, setSelectedType] = useState<'All' | 'payload'>('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [copiedItems, setCopiedItems] = useState<Set<string>>(new Set());
  const [autoLoaded, setAutoLoaded] = useState(false);
  const [loadingLatest, setLoadingLatest] = useState(false);
  const [loadingPayloads, setLoadingPayloads] = useState(false);
  const [sortBy, setSortBy] = useState<'newest' | 'oldest' | 'stars' | 'name'>('newest');
  const [notification, setNotification] = useState<string | null>(null);

  // Check for URL search parameters on mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const searchParam = urlParams.get('search');
    if (searchParam) {
      setSearchTerm(searchParam);
    }
  }, []);

  // Fetch tools data from API on component mount
  useEffect(() => {
    const fetchTools = async () => {
      try {
        setLoading(true);
        // Load without forcing fresh GitHub data on initial load
        const response = await fetch(`/api/tools?source=all&t=${Date.now()}`, {
          cache: 'no-store',
          headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
          }
        });
        if (!response.ok) {
          throw new Error('Failed to fetch tools data');
        }
        const data = await response.json();
        // Handle both old array format and new structured format
        const toolsArray = Array.isArray(data) ? data : (data.tools || []);
        setTools(toolsArray);
        setError(null);
      } catch (err) {
        console.error('Error fetching tools:', err);
        setError('Failed to load tools. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    fetchTools();
  }, []);

  // Auto-load latest tools and payloads after initial load
  useEffect(() => {
    if (!loading && !error && tools.length > 0 && !autoLoaded) {
      setAutoLoaded(true);
      // Auto-fetch latest tools first (prioritize recent content)
      setTimeout(() => {
        fetchLatestTools(true); // Silent fetch
      }, 500);
      // Then fetch payloads
      setTimeout(() => {
        fetchPayloads(true); // Silent fetch
      }, 1500);
      // Finally get some category-specific latest tools
      setTimeout(() => {
        fetchCategoryTools('cve', true); // Get latest CVEs silently
      }, 3000);
    }
  }, [loading, error, tools.length, autoLoaded]);

  // Filter tools based on search and tag filters
  useEffect(() => {
    let filtered = tools;

    // Filter by tag
    if (selectedTag !== 'All') {
      const tagLower = selectedTag.toLowerCase();
      filtered = filtered.filter(tool => Array.isArray(tool.tags) && tool.tags.some(t => String(t).toLowerCase() === tagLower));
    }

    // Filter by category
    if (selectedCategory !== 'All') {
      const catLower = selectedCategory.toLowerCase();
      filtered = filtered.filter(tool => (tool.category || '').toLowerCase() === catLower);
    }

    // Filter by type (e.g., payloads)
    if (selectedType !== 'All') {
      if (selectedType === 'payload') {
        filtered = filtered.filter(tool => tool.type === 'payload' || !!tool.code);
      }
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(tool =>
        tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        tool.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }

    // Sort based on selected criteria (non-mutating and robust fallbacks)
    const getDate = (t: Tool) => {
      const d = (t.publishedAt || (t as any).lastUpdated || '').toString();
      const ts = Date.parse(d);
      return isNaN(ts) ? 0 : ts;
    };

    const sorted = [...filtered].sort((a, b) => {
      switch (sortBy) {
        case 'newest': {
          const dateA = getDate(a);
          const dateB = getDate(b);
          return dateB - dateA; // Newest first
        }
        case 'oldest': {
          const dateA = getDate(a);
          const dateB = getDate(b);
          return dateA - dateB; // Oldest first
        }
        case 'stars':
          return (b.stars || 0) - (a.stars || 0); // Most stars first
        case 'name':
          return (a.name || '').toLowerCase().localeCompare((b.name || '').toLowerCase()); // Alphabetical
        default:
          return 0;
      }
    });

    setFilteredTools(sorted);
  }, [tools, selectedTag, selectedCategory, selectedType, searchTerm, sortBy]);

const copyToClipboard = (text: string, itemId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItems(prev => new Set([...prev, itemId]));
    setTimeout(() => {
      setCopiedItems(prev => {
        const newSet = new Set(prev);
        newSet.delete(itemId);
        return newSet;
      });
    }, 2000);
  };

  const getToolIcon = (tool: Tool) => {
    if (tool.type === 'payload' || tool.code) return <FaCode className="text-cyber-purple" />;
    if (tool.type === 'cheatsheet') return <FaFileAlt className="text-cyber-blue" />;
    return <FaGithub className="text-cyber-green" />;
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) return '1 day ago';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
    return `${Math.floor(diffDays / 365)} years ago`;
  };

  const isRecent = (dateString?: string) => {
    if (!dateString) return false;
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays <= 7; // Consider recent if within last week
  };

  const getAllTags = () => {
    const tags = new Set<string>();
    if (Array.isArray(tools) && tools.length > 0) {
      tools.forEach(tool => {
        if (tool.tags && Array.isArray(tool.tags)) {
          tool.tags.forEach(tag => tags.add(tag));
        }
      });
    }
    return Array.from(tags).sort();
  };

  // Fetch latest tools from GitHub and external sources
  const fetchLatestTools = async (silent = false) => {
    try {
      if (!silent) {
        setRefreshing(true);
        setRefreshError(null);
      } else {
        setLoadingLatest(true);
      }
      const response = await fetch(`/api/tools/latest?limit=30&fresh=true&t=${Date.now()}`, {
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      if (!response.ok) {
        throw new Error('Failed to fetch latest tools');
      }
      const data = await response.json();
      const latestTools = data.tools || [];
      
      // Merge with existing tools (avoid duplicates by ID and name)
      const existingIds = new Set(tools.map(tool => tool.id));
      const existingNames = new Set(tools.map(tool => tool.name.toLowerCase()));
      const newTools = latestTools.filter((tool: Tool) => 
        !existingIds.has(tool.id) && !existingNames.has(tool.name.toLowerCase())
      );
      
      if (newTools.length > 0) {
        // Sort new tools by date (newest first) before adding
        const sortedNewTools = newTools.sort((a: Tool, b: Tool) => {
          const dateA = new Date(a.publishedAt || '1970-01-01').getTime();
          const dateB = new Date(b.publishedAt || '1970-01-01').getTime();
          return dateB - dateA;
        });
        setTools(prevTools => {
          // Final deduplication check when adding to prevent React key errors
          const combinedTools = [...sortedNewTools, ...prevTools];
          const uniqueTools = combinedTools.filter((tool, index, self) => 
            index === self.findIndex(t => t.id === tool.id)
          );
          return uniqueTools;
        });
        
        // Show notification for non-silent fetches
        if (!silent) {
          setNotification(`✅ Added ${newTools.length} latest tools`);
          setTimeout(() => setNotification(null), 3000);
        }
      }
    } catch (err) {
      console.error('Error fetching latest tools:', err);
      if (!silent) {
        setRefreshError('Failed to fetch latest tools. Please try again.');
      }
    } finally {
      if (!silent) {
        setRefreshing(false);
      } else {
        setLoadingLatest(false);
      }
    }
  };

  // Fetch fresh GitHub tools
  const fetchFreshTools = async () => {
    try {
      setRefreshing(true);
      setRefreshError(null);
      const response = await fetch(`/api/tools?fresh=true&t=${Date.now()}`, {
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      if (!response.ok) {
        throw new Error('Failed to fetch fresh tools');
      }
      const data = await response.json();
      const toolsArray = Array.isArray(data) ? data : (data.tools || []);
      setTools(toolsArray);
    } catch (err) {
      console.error('Error fetching fresh tools:', err);
      setRefreshError('Failed to refresh tools. Please try again.');
    } finally {
      setRefreshing(false);
    }
  };

  // Fetch specific category tools
  const fetchCategoryTools = async (category: string, silent = false) => {
    try {
      if (!silent) {
        setRefreshing(true);
        setRefreshError(null);
      }
      const response = await fetch(`/api/tools/latest?category=${category}&limit=15&t=${Date.now()}`, {
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      if (!response.ok) {
        throw new Error(`Failed to fetch ${category} tools`);
      }
      const data = await response.json();
      const categoryTools = data.tools || [];
      
      // Merge with existing tools (avoid duplicates by ID and name)
      const existingIds = new Set(tools.map(tool => tool.id));
      const existingNames = new Set(tools.map(tool => tool.name.toLowerCase()));
      const newTools = categoryTools.filter((tool: Tool) => 
        !existingIds.has(tool.id) && !existingNames.has(tool.name.toLowerCase())
      );
      
      if (newTools.length > 0) {
        // Sort new tools by date (newest first) before adding
        const sortedNewTools = newTools.sort((a: Tool, b: Tool) => {
          const dateA = new Date(a.publishedAt || '1970-01-01').getTime();
          const dateB = new Date(b.publishedAt || '1970-01-01').getTime();
          return dateB - dateA;
        });
        setTools(prevTools => {
          // Final deduplication check when adding to prevent React key errors
          const combinedTools = [...sortedNewTools, ...prevTools];
          const uniqueTools = combinedTools.filter((tool, index, self) => 
            index === self.findIndex(t => t.id === tool.id)
          );
          return uniqueTools;
        });
        // Focus the UI on this category only for interactive (non-silent) calls
        if (!silent) {
          setSelectedCategory(category);
          setSelectedType('All');
          setSelectedTag('All');
        }
      }
    } catch (err) {
      console.error(`Error fetching ${category} tools:`, err);
      if (!silent) {
        setRefreshError(`Failed to fetch ${category} tools. Please try again.`);
      }
    } finally {
      if (!silent) {
        setRefreshing(false);
      }
    }
  };

  // Fetch payloads
  const fetchPayloads = async (silent = false) => {
    try {
      if (!silent) {
        setRefreshing(true);
        setRefreshError(null);
      } else {
        setLoadingPayloads(true);
      }
      const response = await fetch(`/api/tools/payloads?fresh=true&limit=50&t=${Date.now()}`, {
        cache: 'no-store',
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      if (!response.ok) {
        throw new Error('Failed to fetch payloads');
      }
      const data = await response.json();
      const payloads = data.payloads || [];
      
      // Convert payloads to tool format and merge
      const payloadTools = payloads.map((payload: any) => ({
        id: payload.id,
        name: payload.name,
        description: payload.description,
        code: payload.code,
        type: payload.type,
        tags: payload.tags,
        source: payload.source,
        category: payload.category,
        language: payload.language,
        publishedAt: payload.lastUpdated || new Date().toISOString(),
        link: undefined
      }));
      
      // Avoid duplicates by ID and name
      const existingIds = new Set(tools.map(tool => tool.id));
      const existingNames = new Set(tools.map(tool => tool.name.toLowerCase()));
      const newPayloads = payloadTools.filter((tool: Tool) => 
        !existingIds.has(tool.id) && !existingNames.has(tool.name.toLowerCase())
      );
      
      if (newPayloads.length > 0) {
        setTools(prevTools => {
          // Final deduplication check when adding to prevent React key errors
          const combinedTools = [...newPayloads, ...prevTools];
          const uniqueTools = combinedTools.filter((tool, index, self) => 
            index === self.findIndex(t => t.id === tool.id)
          );
          return uniqueTools;
        });
        // Focus on payloads view only for interactive (non-silent) calls
        if (!silent) {
          setSelectedType('payload');
          setSelectedCategory('All');
          setSelectedTag('All');
        }
      }
    } catch (err) {
      console.error('Error fetching payloads:', err);
      if (!silent) {
        setRefreshError('Failed to fetch payloads. Please try again.');
      }
    } finally {
      if (!silent) {
        setRefreshing(false);
      } else {
        setLoadingPayloads(false);
      }
    }
  };

  return (
    <Layout>
      <div className="py-4 sm:py-6 lg:py-8">
        <header className="text-center mb-8 sm:mb-10 lg:mb-12 px-2 sm:px-4">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-cyber font-bold text-green-600 dark:text-cyber-green" data-text="Tools & Payloads Vault">
            Tools & Payloads Vault
          </h1>
          <p className="text-base sm:text-lg text-blue-600 dark:text-cyber-blue mt-3 sm:mt-4">
            [ Arsenal of exploitation tools and security resources ]
          </p>
        </header>

        {/* Loading State */}
        {loading && (
          <div className="text-center py-8 sm:py-10 lg:py-12">
            <FaSpinner className="text-cyber-green text-3xl sm:text-4xl animate-spin mx-auto mb-3 sm:mb-4" />
            <p className="text-cyber-green text-base sm:text-lg">Loading tools...</p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="bg-red-900/20 border border-red-500/50 p-4 sm:p-6 rounded-lg mb-6 sm:mb-8 text-center mx-2 sm:mx-4">
            <p className="text-red-400 text-base sm:text-lg mb-3 sm:mb-4">{error}</p>
            <button
              onClick={() => window.location.reload()}
              className="bg-red-500 text-white px-4 py-2 rounded font-bold hover:bg-red-600 transition-colors text-sm sm:text-base"
            >
              Retry
            </button>
          </div>
        )}

        {/* Filters and Tools Grid */}
        {!loading && !error && (
          <>
            {/* Stats Display */}
            <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-3 sm:p-4 lg:p-6 mb-4 sm:mb-6 mx-2 sm:mx-0">
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 sm:gap-4 text-center">
                <div>
                  <div className="text-xl sm:text-2xl font-bold text-cyber-green">{filteredTools.length}</div>
                  <div className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">Showing</div>
                </div>
                <div>
                  <div className="text-xl sm:text-2xl font-bold text-cyber-blue">{tools.length}</div>
                  <div className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">Total Tools</div>
                </div>
                <div>
                  <div className="text-xl sm:text-2xl font-bold text-cyber-pink">{tools.filter(t => t.code).length}</div>
                  <div className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">Payloads</div>
                </div>
                <div className="hidden sm:block">
                  <div className="text-xl sm:text-2xl font-bold text-cyber-purple">{getAllTags().length}</div>
                  <div className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">Categories</div>
                </div>
                <div className="hidden lg:block">
                  <div className="text-xl sm:text-2xl font-bold text-red-400">{tools.filter(t => isRecent(t.publishedAt)).length}</div>
                  <div className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">Recent (7d)</div>
                </div>
              </div>
            </div>

            {/* Notification */}
            {notification && (
              <div className="bg-green-900/20 border border-green-500/50 p-3 rounded-lg mb-4 text-center animate-fade-in mx-2 sm:mx-0">
                <p className="text-green-400 text-xs sm:text-sm">{notification}</p>
              </div>
            )}

            <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 sm:p-6 mb-6 sm:mb-8 mx-2 sm:mx-0">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
                {/* Search */}
                <div className="relative sm:col-span-2 lg:col-span-1">
                  <input
                    type="text"
                    placeholder="Search tools..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full rounded bg-black/20 light:bg-white/30 backdrop-blur-sm border border-white/10 pl-3 sm:pl-4 pr-3 sm:pr-4 py-2 text-foreground placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyber-green focus:border-transparent text-sm sm:text-base"
                  />
                </div>

                {/* Tag Filter */}
                <select
                  value={selectedTag}
                  onChange={(e) => setSelectedTag(e.target.value)}
                  className="rounded bg-black/20 light:bg-white/30 backdrop-blur-sm border border-white/10 px-3 sm:px-4 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-cyber-green focus:border-transparent [&>option]:text-foreground [&>option]:bg-black/80 light:[&>option]:bg-white/80 text-sm sm:text-base"
                >
                  <option value="All">All Tags</option>
                  {getAllTags().map(tag => (
                    <option key={tag} value={tag}>{tag}</option>
                  ))}
                </select>

                {/* Sort By */}
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as 'newest' | 'oldest' | 'stars' | 'name')}
                  className="rounded bg-black/20 light:bg-white/30 backdrop-blur-sm border border-white/10 px-3 sm:px-4 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-cyber-blue focus:border-transparent [&>option]:text-foreground [&>option]:bg-black/80 light:[&>option]:bg-white/80 text-sm sm:text-base"
                >
                  <option value="newest">🕒 Newest First</option>
                  <option value="oldest">⏰ Oldest First</option>
                  <option value="stars">⭐ Most Stars</option>
                  <option value="name">🔤 Alphabetical</option>
                </select>

                {/* Clear Filters */}
                <button
                  onClick={() => {
                    setSearchTerm('');
                    setSelectedTag('All');
                    setSelectedCategory('All');
                    setSelectedType('All');
                    setSortBy('newest');
                  }}
                  className="bg-cyber-green text-black px-3 sm:px-4 py-2 rounded font-bold border border-white/10 hover:bg-cyber-green/90 transition-colors text-sm sm:text-base"
                >
                  Clear Filters
                </button>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-3 sm:p-4 mb-6 sm:mb-8 mx-2 sm:mx-0">
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2 sm:gap-3">
                <button
                  onClick={() => { fetchLatestTools(); setSelectedCategory('All'); setSelectedType('All'); setSelectedTag('All'); setSortBy('newest'); }}
                  disabled={refreshing || loadingLatest}
                  className="bg-cyber-blue text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-cyber-green transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  {loadingLatest ? <FaSpinner className="animate-spin" /> : <FaStar />}
                  <span className="hidden sm:inline">{loadingLatest ? 'Loading...' : 'Latest Tools'}</span>
                  <span className="sm:hidden">Latest</span>
                </button>

                <button
                  onClick={() => fetchPayloads()}
                  disabled={refreshing || loadingPayloads}
                  className="bg-cyber-pink text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-cyber-purple transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  {loadingPayloads ? <FaSpinner className="animate-spin" /> : <FaCode />}
                  <span className="hidden sm:inline">{loadingPayloads ? 'Loading...' : 'Payloads'}</span>
                  <span className="sm:hidden">Payloads</span>
                </button>

                <button
                  onClick={() => fetchCategoryTools('owasp')}
                  disabled={refreshing}
                  className="bg-orange-500 text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-orange-600 transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  <FaExternalLinkAlt />
                  <span>OWASP</span>
                </button>

                <button
                  onClick={() => fetchCategoryTools('nuclei')}
                  disabled={refreshing}
                  className="bg-purple-500 text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-purple-600 transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  <FaFileAlt />
                  <span>Nuclei</span>
                </button>

                <button
                  onClick={() => fetchCategoryTools('kali')}
                  disabled={refreshing}
                  className="bg-green-600 text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-green-700 transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  <FaCode />
                  <span className="hidden sm:inline">Kali Tools</span>
                  <span className="sm:hidden">Kali</span>
                </button>

                <button
                  onClick={() => fetchCategoryTools('metasploit')}
                  disabled={refreshing}
                  className="bg-red-600 text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-red-700 transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  <FaExclamationTriangle />
                  <span className="hidden sm:inline">Metasploit</span>
                  <span className="sm:hidden">MSF</span>
                </button>

                <button
                  onClick={() => fetchCategoryTools('h1')}
                  disabled={refreshing}
                  className="bg-indigo-500 text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-indigo-600 transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  <FaStar />
                  <span className="hidden sm:inline">HackerOne</span>
                  <span className="sm:hidden">H1</span>
                </button>

                <button
                  onClick={() => { fetchFreshTools(); setSelectedCategory('All'); setSelectedType('All'); setSelectedTag('All'); }}
                  disabled={refreshing}
                  className="bg-cyber-purple text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-cyber-pink transition-colors flex items-center justify-center space-x-1 sm:space-x-2 disabled:opacity-50 text-xs sm:text-sm"
                >
                  <FaSync className={refreshing ? "animate-spin" : ""} />
                  <span className="hidden sm:inline">Refresh All</span>
                  <span className="sm:hidden">Refresh</span>
                </button>

                <button
                  onClick={() => {
                    setSortBy('newest');
                    setSelectedTag('All');
                    setSelectedCategory('All');
                    setSelectedType('All');
                    setSearchTerm('');
                  }}
                  className="bg-yellow-500 text-white px-2 sm:px-3 py-2 rounded font-bold hover:bg-yellow-600 transition-colors flex items-center justify-center space-x-1 sm:space-x-2 text-xs sm:text-sm col-span-2 sm:col-span-1"
                >
                  <FaStar />
                  <span className="hidden sm:inline">Show Latest</span>
                  <span className="sm:hidden">Reset</span>
                </button>
              </div>
              {(refreshing || loadingLatest || loadingPayloads) && (
                <div className="text-center mt-3">
                  <p className="text-cyber-blue text-xs sm:text-sm">
                    {refreshing ? 'Fetching tools...' : 
                     loadingLatest ? 'Getting latest tools...' : 
                     'Loading payloads...'}
                  </p>
                </div>
              )}
              {refreshError && (
                <div className="bg-red-900/20 border border-red-500/50 p-3 rounded mt-3 flex items-center justify-center space-x-2">
                  <FaExclamationTriangle className="text-red-400 flex-shrink-0" />
                  <p className="text-red-400 text-xs sm:text-sm">{refreshError}</p>
                  <button
                    onClick={() => setRefreshError(null)}
                    className="text-red-400 hover:text-red-300 ml-2 flex-shrink-0"
                  >
                    ×
                  </button>
                </div>
              )}
            </div>

            {/* Tools Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6 px-2 sm:px-0">
              {filteredTools.map((tool, index) => (
                <div
                  key={tool.id}
                  className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 sm:p-6 transition-all duration-300 group animate-fade-in"
                  style={{ animationDelay: `${index * 100}ms` }}
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3 sm:mb-4">
                    <div className="flex items-center space-x-2 sm:space-x-3 flex-1 min-w-0">
                      {getToolIcon(tool)}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center space-x-2 flex-wrap">
                          <h3 className="text-base sm:text-lg font-bold text-cyber-green group-hover:text-cyber-blue transition-colors truncate">
                            {tool.name}
                          </h3>
                          {isRecent(tool.publishedAt) && (
                            <span className="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded border border-red-500/30 animate-pulse flex-shrink-0">
                              NEW
                            </span>
                          )}
                        </div>
                        <div className="flex items-center space-x-2 mt-1 text-xs">
                          {tool.source && (
                            <p className="text-gray-600 dark:text-gray-500 truncate">{tool.source}</p>
                          )}
                          {tool.publishedAt && (
                            <>
                              <span className="text-gray-500 dark:text-gray-600 flex-shrink-0">•</span>
                              <p className="text-cyber-blue flex-shrink-0">{formatDate(tool.publishedAt)}</p>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end space-y-1 flex-shrink-0">
                      {tool.type && (
                        <span className="px-2 py-1 bg-cyber-purple/20 text-cyber-purple text-xs rounded border border-cyber-purple/30">
                          {tool.type}
                        </span>
                      )}
                      {tool.stars && tool.stars > 0 && (
                        <div className="flex items-center space-x-1 text-xs text-yellow-400">
                          <FaStar size={10} />
                          <span>{tool.stars}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Description */}
                  <div className="mb-3 sm:mb-4">
                    <p className="text-sm text-gray-700 dark:text-gray-300 line-clamp-3 mb-2 leading-relaxed">
                      {tool.description}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {tool.category && (
                        <span className="inline-block px-2 py-1 bg-cyber-blue/20 text-cyber-blue text-xs rounded border border-cyber-blue/30">
                          {tool.category}
                        </span>
                      )}
                      {tool.language && (
                        <span className="inline-block px-2 py-1 bg-cyber-green/20 text-cyber-green text-xs rounded border border-cyber-green/30">
                          {tool.language}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Code Block (if present) */}
                  {tool.code && (
                    <div className="bg-terminal-bg border border-cyber-green/50 p-3 rounded mb-3 sm:mb-4 relative">
                      <div className="max-h-32 sm:max-h-48 overflow-y-auto">
                        <pre className="text-cyber-green text-xs sm:text-sm font-mono whitespace-pre-wrap break-words"><code>{tool.code}</code></pre>
                      </div>
                      <button
                        onClick={() => copyToClipboard(tool.code!, tool.id)}
                        className="absolute top-2 right-2 text-gray-600 dark:text-gray-400 hover:text-cyber-green transition-colors bg-terminal-bg/80 p-1 rounded"
                        title="Copy to clipboard"
                      >
                        <FaCopy size={12} />
                      </button>
                      {copiedItems.has(tool.id) && (
                        <span className="absolute top-2 right-10 sm:right-12 text-cyber-green text-xs bg-terminal-bg/80 px-2 py-1 rounded copy-status">
                          Copied!
                        </span>
                      )}
                    </div>
                  )}

                  {/* Tags */}
                  <div className="flex flex-wrap gap-1 sm:gap-2 mb-3 sm:mb-4">
                    {tool.tags.slice(0, 4).map(tag => (
                      <span
                        key={tag}
                        className="px-2 py-1 bg-cyber-green/10 text-cyber-green text-xs rounded border border-cyber-green/30 cursor-pointer hover:bg-cyber-green/20 transition-colors"
                        onClick={() => setSelectedTag(tag)}
                      >
                        {tag}
                      </span>
                    ))}
                    {tool.tags.length > 4 && (
                      <span className="px-2 py-1 bg-gray-500/20 text-gray-400 text-xs rounded border border-gray-500/30">
                        +{tool.tags.length - 4}
                      </span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex flex-col sm:flex-row justify-between items-stretch sm:items-center space-y-2 sm:space-y-0 sm:space-x-2">
                    {tool.link && (
                      <a
                        href={tool.link}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center justify-center space-x-2 bg-cyber-green text-black px-3 sm:px-4 py-2 rounded font-semibold hover:bg-cyber-blue transition-colors text-sm"
                      >
                        <FaExternalLinkAlt size={12} />
                        <span>View</span>
                      </a>
                    )}
                    {tool.code && (
                      <button
                        onClick={() => copyToClipboard(tool.code!, tool.id)}
                        className="flex items-center justify-center space-x-2 bg-cyber-purple text-white px-3 sm:px-4 py-2 rounded font-semibold hover:bg-cyber-pink transition-colors text-sm"
                      >
                        <FaCopy size={12} />
                        <span>{copiedItems.has(tool.id) ? 'Copied!' : 'Copy'}</span>
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {filteredTools.length === 0 && (
              <div className="text-center py-8 sm:py-12">
                <p className="text-gray-600 dark:text-gray-400 text-base sm:text-lg">No tools found matching your criteria.</p>
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
};

export default Tools;
