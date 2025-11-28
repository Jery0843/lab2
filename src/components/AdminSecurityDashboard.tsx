'use client';

import { useState, useEffect } from 'react';
import { FaShieldAlt, FaEye, FaTrash, FaSync, FaExclamationTriangle } from 'react-icons/fa';

interface SecurityLog {
  id: number;
  action: string;
  data: string;
  ip_address: string;
  user_agent: string;
  timestamp: string;
}

interface UnauthorizedLog {
  id: number;
  ip_address: string;
  user_agent: string;
  path: string;
  reason: string;
  country: string;
  region: string;
  city: string;
  referer: string;
  timestamp: string;
}

interface SessionStats {
  total: number;
  active: number;
  expired: number;
}

export default function AdminSecurityDashboard() {
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [unauthorizedLogs, setUnauthorizedLogs] = useState<UnauthorizedLog[]>([]);
  const [sessionStats, setSessionStats] = useState<SessionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSecurityData();
  }, []);

  const fetchSecurityData = async () => {
    try {
      setLoading(true);
      
      // Fetch security logs
      const logsResponse = await fetch('/api/admin/logs', {
        credentials: 'include'
      });
      
      if (logsResponse.ok) {
        const logsData = await logsResponse.json();
        console.log('Security logs data:', logsData);
        const logs = logsData.logs || logsData;
        setLogs(Array.isArray(logs) ? logs.slice(0, 25) : []);
      } else {
        console.error('Failed to fetch security logs:', logsResponse.status);
      }

      // Fetch unauthorized access logs
      const unauthorizedResponse = await fetch('/api/admin/unauthorized-logs', {
        credentials: 'include'
      });
      
      console.log('Unauthorized response status:', unauthorizedResponse.status);
      
      if (unauthorizedResponse.ok) {
        const unauthorizedData = await unauthorizedResponse.json();
        console.log('Unauthorized logs raw response:', unauthorizedData);
        console.log('Is array?', Array.isArray(unauthorizedData));
        console.log('Length:', unauthorizedData?.length);
        setUnauthorizedLogs(Array.isArray(unauthorizedData) ? unauthorizedData.slice(0, 25) : []);
      } else {
        const errorText = await unauthorizedResponse.text();
        console.error('Failed to fetch unauthorized logs:', unauthorizedResponse.status, errorText);
      }

      // Fetch session statistics
      const sessionResponse = await fetch('/api/admin/cleanup-sessions', {
        credentials: 'include'
      });
      
      if (sessionResponse.ok) {
        const sessionData = await sessionResponse.json();
        setSessionStats(sessionData.stats);
      }

    } catch (error) {
      console.error('Error fetching security data:', error);
      setError('Failed to load security data');
    } finally {
      setLoading(false);
    }
  };

  const cleanupSessions = async () => {
    try {
      const response = await fetch('/api/admin/cleanup-sessions', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        alert(data.message);
        fetchSecurityData(); // Refresh data
      } else {
        alert('Failed to cleanup sessions');
      }
    } catch (error) {
      console.error('Error cleaning up sessions:', error);
      alert('Error cleaning up sessions');
    }
  };

  const getSeverityColor = (action: string) => {
    if (action.includes('failure') || action.includes('rate_limit')) {
      return 'text-red-400 bg-red-900/20 border-red-500/50';
    }
    if (action.includes('login') || action.includes('logout')) {
      return 'text-green-400 bg-green-900/20 border-green-500/50';
    }
    return 'text-blue-400 bg-blue-900/20 border-blue-500/50';
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const parseLogData = (dataString: string) => {
    try {
      return JSON.parse(dataString);
    } catch {
      return {};
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="text-cyber-green font-mono">Loading security dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-cyber-green flex items-center">
          <FaShieldAlt className="mr-3" />
          Security Dashboard
        </h2>
        <div className="flex space-x-3">
          <button
            onClick={fetchSecurityData}
            className="bg-cyber-blue text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition-colors font-bold border-2 border-cyber-blue"
          >
            <FaSync className="inline mr-2" />
            Refresh
          </button>
          <button
            onClick={cleanupSessions}
            className="bg-cyber-purple text-white px-4 py-2 rounded-lg hover:bg-purple-600 transition-colors font-bold border-2 border-cyber-purple"
          >
            <FaTrash className="inline mr-2" />
            Cleanup Sessions
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/20 border border-red-500/50 text-red-400 p-4 rounded-lg">
          <FaExclamationTriangle className="inline mr-2" />
          {error}
        </div>
      )}

      {/* Session Statistics */}
      {sessionStats && (
        <div className="grid grid-cols-3 gap-4">
          <div className="rounded-xl backdrop-blur-sm bg-black/40 border border-cyber-green/30 p-4">
            <h3 className="text-lg font-bold text-cyber-green mb-2">Total Sessions</h3>
            <p className="text-3xl font-bold text-white">{sessionStats.total}</p>
          </div>
          <div className="rounded-xl backdrop-blur-sm bg-black/40 border border-green-500/30 p-4">
            <h3 className="text-lg font-bold text-green-400 mb-2">Active Sessions</h3>
            <p className="text-3xl font-bold text-white">{sessionStats.active}</p>
          </div>
          <div className="rounded-xl backdrop-blur-sm bg-black/40 border border-red-500/30 p-4">
            <h3 className="text-lg font-bold text-red-400 mb-2">Expired Sessions</h3>
            <p className="text-3xl font-bold text-white">{sessionStats.expired}</p>
          </div>
        </div>
      )}

      {/* Unauthorized Access Logs */}
      <div className="rounded-2xl backdrop-blur-sm bg-black/40 border border-red-500/30 p-6">
        <h3 className="text-xl font-bold text-red-400 mb-4 flex items-center">
          <FaExclamationTriangle className="mr-2" />
          Unauthorized Access Attempts (Last 25)
        </h3>
        
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {unauthorizedLogs.length === 0 ? (
            <p className="text-gray-400">No unauthorized access attempts</p>
          ) : (
            unauthorizedLogs.map((log) => (
              <div
                key={log.id}
                className="p-3 rounded-lg border bg-red-900/20 border-red-500/50 text-red-400"
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="font-bold text-sm uppercase">{log.reason.replace(/_/g, ' ')}</span>
                  <span className="text-xs opacity-75">{formatTimestamp(log.timestamp)}</span>
                </div>
                <div className="text-sm space-y-1">
                  <div><strong>IP:</strong> {log.ip_address}</div>
                  <div><strong>Location:</strong> {log.city}, {log.region}, {log.country}</div>
                  <div><strong>Path:</strong> {log.path}</div>
                  {log.referer && (
                    <div><strong>Referer:</strong> {log.referer}</div>
                  )}
                  <div className="text-xs opacity-60 truncate">
                    <strong>User Agent:</strong> {log.user_agent}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Security Logs */}
      <div className="rounded-2xl backdrop-blur-sm bg-black/40 border border-cyber-green/30 p-6">
        <h3 className="text-xl font-bold text-cyber-green mb-4 flex items-center">
          <FaEye className="mr-2" />
          Recent Security Events (Last 25)
        </h3>
        
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {logs.length === 0 ? (
            <p className="text-gray-400">No security logs found</p>
          ) : (
            logs.map((log) => {
              const logData = parseLogData(log.data);
              return (
                <div
                  key={log.id}
                  className={`p-3 rounded-lg border ${getSeverityColor(log.action)}`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="font-bold text-sm uppercase">{log.action.replace(/_/g, ' ')}</span>
                    <span className="text-xs opacity-75">{formatTimestamp(log.timestamp)}</span>
                  </div>
                  <div className="text-sm space-y-1">
                    <div><strong>IP:</strong> {log.ip_address}</div>
                    {logData.username && (
                      <div><strong>Username:</strong> {logData.username}</div>
                    )}
                    {logData.details && (
                      <div><strong>Details:</strong> {JSON.stringify(logData.details)}</div>
                    )}
                    <div className="text-xs opacity-60 truncate">
                      <strong>User Agent:</strong> {log.user_agent}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}