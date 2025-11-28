'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { FaLock, FaHome, FaExclamationTriangle } from 'react-icons/fa';

export default function UnauthorizedPage() {
  useEffect(() => {
    // Log page view for unauthorized access
    fetch('/api/admin/unauthorized-logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        path: '/admin/unauthorized',
        reason: 'unauthorized_page_view'
      })
    }).catch(() => {}); // Silent fail
  }, []);
  return (
    <div className="min-h-screen bg-terminal-bg flex items-center justify-center px-4">
      <div className="max-w-md w-full text-center">
        <div className="mb-8">
          <FaLock className="text-6xl text-red-500 mx-auto mb-4 animate-pulse" />
          <h1 className="text-4xl font-cyber font-bold text-red-500 mb-2">
            UNAUTHORIZED
          </h1>
          <div className="flex items-center justify-center text-red-400 mb-4">
            <FaExclamationTriangle className="mr-2" />
            <span className="text-lg">Access Denied</span>
          </div>
        </div>
        
        <div className="bg-black/40 border border-red-500/30 rounded-lg p-6 mb-6">
          <p className="text-gray-300 mb-4">
            You do not have permission to access this area.
          </p>
          <p className="text-sm text-gray-400">
            This incident has been logged.
          </p>
        </div>

        <Link 
          href="/"
          className="inline-flex items-center bg-cyber-green text-black px-6 py-3 rounded-lg hover:bg-green-600 transition-colors font-bold"
        >
          <FaHome className="mr-2" />
          Return Home
        </Link>
      </div>
    </div>
  );
}