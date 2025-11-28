'use client';

import { useState } from 'react';
import Layout from '@/components/Layout';

export default function SimpleAdmin() {
  const [message, setMessage] = useState('');
  const [currentStats, setCurrentStats] = useState(null);

  const testGet = async () => {
    try {
      const response = await fetch('/api/admin/htb-stats');
      const data = await response.json();
      setCurrentStats(data);
      setMessage(`GET successful: ${JSON.stringify(data, null, 2)}`);
    } catch (error) {
      setMessage(`GET error: ${error}`);
    }
  };

  const testPost = async () => {
    try {
      const testData = {
        machinesPwned: 15,
        globalRanking: 800,
        finalScore: 200,
        htbRank: 'Pro Hacker',
        lastUpdated: new Date().toISOString()
      };

      const response = await fetch('/api/admin/htb-stats', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(testData),
      });

      const result = await response.json();
      setMessage(`POST successful: ${JSON.stringify(result, null, 2)}`);
    } catch (error) {
      setMessage(`POST error: ${error}`);
    }
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-4xl font-cyber font-bold mb-8 text-center">
          Simple Admin Test
        </h1>

        <div className="max-w-2xl mx-auto bg-card-bg border border-cyber-green/30 p-8 rounded-lg">
          <div className="space-y-4">
            <button
              onClick={testGet}
              className="w-full bg-cyber-blue text-white px-6 py-3 rounded-lg font-bold hover:bg-cyber-blue/80 transition-all duration-300"
            >
              Test GET /api/admin/htb-stats
            </button>

            <button
              onClick={testPost}
              className="w-full bg-cyber-green text-black px-6 py-3 rounded-lg font-bold hover:bg-cyber-green/80 transition-all duration-300"
            >
              Test POST /api/admin/htb-stats
            </button>
          </div>

          {message && (
            <div className="mt-6 p-4 bg-gray-800 border border-cyber-green/50 rounded-lg">
              <pre className="text-sm text-green-300 whitespace-pre-wrap overflow-auto">
                {message}
              </pre>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
