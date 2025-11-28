'use client';

import { useState, useEffect } from 'react';
import Layout from '@/components/Layout';

interface HTBStats {
  machinesPwned: number;
  globalRanking: number;
  finalScore: number;
  htbRank: string;
  lastUpdated: string;
}

export default function AdminHTBStats() {
  const [stats, setStats] = useState<HTBStats>({
    machinesPwned: 11,
    globalRanking: 891,
    finalScore: 164,
    htbRank: 'Hacker',
    lastUpdated: new Date().toISOString()
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [debugInfo, setDebugInfo] = useState('');

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/admin/htb-stats-d1');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      console.log('Fetched stats:', data);
      setStats(data);
      setMessage('');
    } catch (error) {
      console.error('Error fetching stats:', error);
      setMessage(`Error loading stats: ${error}`);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const updatedStats = {
        ...stats,
        lastUpdated: new Date().toISOString()
      };

      const response = await fetch('/api/admin/htb-stats-d1', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(updatedStats),
      });

      if (response.ok) {
        setMessage('HTB stats updated successfully!');
        setStats(updatedStats);
      } else {
        setMessage('Error updating stats');
      }
    } catch (error) {
      console.error('Error updating stats:', error);
      setMessage('Error updating stats');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field: keyof HTBStats, value: string | number) => {
    setStats(prev => ({
      ...prev,
      [field]: value
    }));
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-4xl font-cyber font-bold mb-8 text-center">
          <span data-text="HTB Stats Admin">
            HTB Stats Admin
          </span>
        </h1>

        <div className="max-w-2xl mx-auto">
          <div className="bg-card-bg border border-cyber-green/30 p-8 rounded-lg">
            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label className="block text-lg font-semibold mb-2 text-cyber-green">
                  Machines Pwned
                </label>
                <input
                  type="number"
                  value={stats.machinesPwned}
                  onChange={(e) => handleInputChange('machinesPwned', parseInt(e.target.value) || 0)}
                  className="w-full px-4 py-2 bg-gray-800 border border-cyber-green/50 rounded-lg text-white focus:border-cyber-green focus:outline-none"
                  min="0"
                />
              </div>

              <div>
                <label className="block text-lg font-semibold mb-2 text-cyber-green">
                  Global Ranking
                </label>
                <input
                  type="number"
                  value={stats.globalRanking}
                  onChange={(e) => handleInputChange('globalRanking', parseInt(e.target.value) || 0)}
                  className="w-full px-4 py-2 bg-gray-800 border border-cyber-green/50 rounded-lg text-white focus:border-cyber-green focus:outline-none"
                  min="0"
                />
              </div>

              <div>
                <label className="block text-lg font-semibold mb-2 text-cyber-green">
                  Final Score
                </label>
                <input
                  type="number"
                  value={stats.finalScore}
                  onChange={(e) => handleInputChange('finalScore', parseInt(e.target.value) || 0)}
                  className="w-full px-4 py-2 bg-gray-800 border border-cyber-green/50 rounded-lg text-white focus:border-cyber-green focus:outline-none"
                  min="0"
                />
              </div>

              <div>
                <label className="block text-lg font-semibold mb-2 text-cyber-green">
                  HTB Rank
                </label>
                <select
                  value={stats.htbRank}
                  onChange={(e) => handleInputChange('htbRank', e.target.value)}
                  className="w-full px-4 py-2 bg-gray-800 border border-cyber-green/50 rounded-lg text-white focus:border-cyber-green focus:outline-none"
                >
                  <option value="Noob">Noob</option>
                  <option value="Script Kiddie">Script Kiddie</option>
                  <option value="Hacker">Hacker</option>
                  <option value="Pro Hacker">Pro Hacker</option>
                  <option value="Elite Hacker">Elite Hacker</option>
                  <option value="Guru">Guru</option>
                  <option value="Omniscient">Omniscient</option>
                </select>
              </div>

              <div className="flex justify-between items-center pt-4">
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyber-green text-black px-8 py-3 rounded-lg font-bold hover:bg-cyber-green/80 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300"
                >
                  {loading ? 'Updating...' : 'Update Stats'}
                </button>

                <button
                  type="button"
                  onClick={fetchStats}
                  className="border border-cyber-green text-cyber-green px-6 py-3 rounded-lg font-bold hover:bg-cyber-green hover:text-black transition-all duration-300"
                >
                  Reload
                </button>
              </div>
            </form>

            {message && (
              <div className={`mt-4 p-3 rounded-lg ${
                message.includes('Error') 
                  ? 'bg-red-900/50 border border-red-500 text-red-300' 
                  : 'bg-green-900/50 border border-green-500 text-green-300'
              }`}>
                {message}
              </div>
            )}

            <div className="mt-6 pt-4 border-t border-cyber-green/30">
              <p className="text-sm text-gray-400">
                Last Updated: {new Date(stats.lastUpdated).toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
