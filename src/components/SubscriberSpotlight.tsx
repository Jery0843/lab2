'use client';

import { useState, useEffect } from 'react';
import { FaUser, FaGlobe, FaCrown, FaShieldAlt } from 'react-icons/fa';

interface Subscriber {
  name: string;
  country: string;
  subscribed_at: string;
  tier_name: string;
}

interface SubscriberSpotlightProps {
  type: 'latest' | 'tiers';
  title: string;
  className?: string;
}

const SubscriberSpotlight = ({ type, title, className = '' }: SubscriberSpotlightProps) => {
  const [subscribers, setSubscribers] = useState<Subscriber[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSubscribers = async () => {
      try {
        const endpoint = type === 'latest' ? '/api/subscribers/latest' : '/api/subscribers/tiers';
        const response = await fetch(endpoint);
        console.log(`Fetching ${type} subscribers from ${endpoint}`);
        
        if (response.ok) {
          const data = await response.json();
          console.log(`${type} subscribers data:`, data);
          setSubscribers(data.subscribers || []);
        } else {
          console.error(`Failed to fetch ${type} subscribers:`, response.status);
          // Add demo data for tiers if no real data
          if (type === 'tiers') {
            setSubscribers([
              { name: 'Anonymous', country: 'Global', subscribed_at: new Date().toISOString(), tier_name: 'sudo' },
              { name: 'Elite User', country: 'Secure', subscribed_at: new Date().toISOString(), tier_name: 'ring-zero' }
            ]);
          }
        }
      } catch (error) {
        console.error('Error fetching subscribers:', error);
        // Add demo data for tiers if error
        if (type === 'tiers') {
          setSubscribers([
            { name: 'Anonymous', country: 'Global', subscribed_at: new Date().toISOString(), tier_name: 'sudo' },
            { name: 'Elite User', country: 'Secure', subscribed_at: new Date().toISOString(), tier_name: 'ring-zero' }
          ]);
        }
      } finally {
        setLoading(false);
      }
    };

    fetchSubscribers();
  }, [type]);

  const getTierIcon = (tier: string) => {
    if (tier === 'ring-zero') return <FaCrown className="text-yellow-400" />;
    if (tier === 'sudo') return <FaShieldAlt className="text-purple-400" />;
    return <FaUser className="text-cyber-green" />;
  };

  const getTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
    
    if (diffInDays === 0) return 'Today';
    if (diffInDays === 1) return '1 day ago';
    if (diffInDays < 7) return `${diffInDays} days ago`;
    return `${Math.floor(diffInDays / 7)} weeks ago`;
  };

  if (loading) {
    return (
      <div className={`rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-4 ${className}`}>
        <h3 className="text-lg font-bold mb-3 text-cyber-green">{title}</h3>
        <div className="space-y-2">
          {[...Array(type === 'latest' ? 4 : 2)].map((_, i) => (
            <div key={i} className="animate-pulse bg-cyber-green/10 h-12 rounded"></div>
          ))}
        </div>
      </div>
    );
  }

  if (subscribers.length === 0) {
    return (
      <div className={`rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-4 ${className}`}>
        <h3 className="text-lg font-bold mb-3 text-cyber-green">{title}</h3>
        <p className="text-gray-400 text-sm">No subscribers yet</p>
      </div>
    );
  }

  return (
    <div className={`rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-4 ${className}`}>
      <h3 className="text-lg font-bold mb-3 text-cyber-green">{title}</h3>
      <div className={`${type === 'latest' ? 'space-y-2' : 'space-y-3 max-h-96 overflow-y-auto scrollbar-thin scrollbar-thumb-cyber-green/50 scrollbar-track-transparent'}`}>
        {subscribers.map((subscriber, index) => (
          type === 'latest' ? (
            <div key={index} className="bg-terminal-bg border-l-4 border-cyber-green p-3 font-mono text-sm hover:bg-cyber-green/5 transition-colors group">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className="text-cyber-green">$</span>
                  <span className="text-cyber-green font-bold">whoami</span>
                  <span className="text-white">{subscriber.name}</span>
                  <span className="text-cyber-blue text-xs px-2 py-1 bg-cyber-blue/10 rounded">
                    [{(subscriber.tier_name || 'user').toUpperCase()}]
                  </span>
                </div>
                <span className="text-cyber-pink text-xs">{getTimeAgo(subscriber.subscribed_at)}</span>
              </div>
              <div className="flex items-center space-x-2 mt-1 text-xs text-gray-400">
                <span className="text-cyber-green">{'>'}</span>
                <span>location:</span>
                <span className="text-cyber-blue">{subscriber.country}</span>
                <span className="text-cyber-green animate-pulse">{'█'}</span>
              </div>
            </div>
          ) : (
            <div key={index} className={`p-4 rounded-lg border-l-4 backdrop-blur-sm transition-all duration-200 hover:bg-black/20 ${
              subscriber.tier_name === 'ring-zero' 
                ? 'bg-yellow-500/5 border-yellow-400' 
                : 'bg-purple-500/5 border-purple-400'
            }`}>
              <div className="flex items-center space-x-3 mb-2">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  subscriber.tier_name === 'ring-zero' 
                    ? 'bg-yellow-400/20 text-yellow-400' 
                    : 'bg-purple-400/20 text-purple-400'
                }`}>
                  {getTierIcon(subscriber.tier_name)}
                </div>
                <div>
                  <h4 className="font-semibold text-white">{subscriber.name}</h4>
                  <span className={`text-xs font-medium ${
                    subscriber.tier_name === 'ring-zero' ? 'text-yellow-400' : 'text-purple-400'
                  }`}>
                    {subscriber.tier_name.replace('-', ' ').toUpperCase()}
                  </span>
                </div>
              </div>
              <div className="text-xs text-gray-400">
                {subscriber.country} • {getTimeAgo(subscriber.subscribed_at)}
              </div>
            </div>
          )
        ))}
      </div>
    </div>
  );
};

export default SubscriberSpotlight;