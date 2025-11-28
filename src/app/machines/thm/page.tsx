'use client';

import { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import MachineCardBase from '@/components/MachineCardBase';
import { FaFilter, FaSearch, FaSync, FaGraduationCap } from 'react-icons/fa';
import thmRoomsData from '@/data/thm-rooms.json';

interface THMRoom {
  id: string;
  title: string;
  slug: string;
  difficulty: string;
  status: string;
  tags: string[];
  writeup: string | null;
  createdAt: string;
  updatedAt: string;
  url: string;
  roomCode: string;
  points: number;
  dateCompleted: string | null;
}

const TryHackMeRooms = () => {
  const [rooms, setRooms] = useState<THMRoom[]>([]);
  const [filteredRooms, setFilteredRooms] = useState<THMRoom[]>([]);

  const [searchTerm, setSearchTerm] = useState('');
  const [filterDifficulty, setFilterDifficulty] = useState('All');
  const [filterStatus, setFilterStatus] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);


  // Fetch rooms from D1 database
  const fetchRooms = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/admin/thm-rooms-d1');
      const data = await response.json();
      
      if (response.ok) {
        // Handle both direct array and object with rooms property
        const roomsArray = Array.isArray(data) ? data : (data.rooms || []);
        setRooms(roomsArray);
      } else {
        // Fallback to default data if API fails
        console.warn('D1 API not available, using fallback data:', data.error);
        setRooms(thmRoomsData);
        setError('Using cached data - database temporarily unavailable');
      }
    } catch (error) {
      console.error('Error fetching THM rooms:', error);
      setRooms(thmRoomsData);
      setError('Failed to load rooms from database');
    } finally {
      setLoading(false);
    }
  };

  // Load rooms data on component mount
  useEffect(() => {
    fetchRooms();
  }, []);

  useEffect(() => {
    let filtered = rooms;

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(room =>
        room.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (Array.isArray(room.tags) && room.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase())))
      );
    }

    // Difficulty filter
    if (filterDifficulty !== 'All') {
      filtered = filtered.filter(room => room.difficulty === filterDifficulty);
    }

    // Status filter
    if (filterStatus !== 'All') {
      filtered = filtered.filter(room => room.status === filterStatus);
    }

    setFilteredRooms(filtered);
  }, [rooms, searchTerm, filterDifficulty, filterStatus]);



  const handleViewWriteup = (room: THMRoom) => {
    // Redirect to individual room page using slug
    window.location.href = `/machines/thm/${room.slug}`;
  };



  const stats = {
    total: rooms.length,
    completed: rooms.filter(r => r.status === 'Completed').length,
    inProgress: rooms.filter(r => r.status === 'In Progress').length,
    easy: rooms.filter(r => r.difficulty === 'Easy').length,
    medium: rooms.filter(r => r.difficulty === 'Medium').length,
    hard: rooms.filter(r => r.difficulty === 'Hard').length,
  };

  return (
    <Layout>
      <div className="py-8">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center space-x-4">
            <div className="bg-cyber-purple/20 p-3 rounded-lg">
              <FaGraduationCap className="text-2xl text-cyber-purple" />
            </div>
            <div>
              <h1 className="text-4xl font-cyber font-bold text-cyber-purple" data-text="TryHackMe Rooms">
                TryHackMe Rooms
              </h1>
              <p className="text-gray-400">Learning-focused cybersecurity challenges</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={fetchRooms}
              disabled={loading}
              className="bg-cyber-purple text-white px-4 py-3 rounded-lg font-bold hover:bg-cyber-pink transition-colors flex items-center space-x-2 border-2 border-cyber-purple"
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
          <div className="mb-6 p-4 rounded-lg bg-cyber-purple/20 border border-cyber-purple/50 text-cyber-purple">
            <div className="flex items-center space-x-2">
              <FaSync className="animate-spin" />
              <span>Loading rooms from database...</span>
            </div>
          </div>
        )}

        {/* Stats Dashboard */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
          <div className="rounded-lg backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 text-center">
            <div className="text-2xl font-bold text-cyber-purple">{stats.total}</div>
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
        </div>

        {/* Filters */}
        <div className="glass-panel p-6 rounded-lg mb-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Search */}
            <div className="relative">
              <FaSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyber-purple" />
              <input
                type="text"
                placeholder="Search rooms..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-terminal-bg border border-cyber-purple/50 pl-10 pr-4 py-2 rounded text-cyber-purple focus:border-cyber-purple focus:outline-none"
              />
            </div>

            {/* Difficulty Filter */}
            <select
              value={filterDifficulty}
              onChange={(e) => setFilterDifficulty(e.target.value)}
              className="bg-terminal-bg border border-cyber-purple/50 px-4 py-2 rounded text-cyber-purple focus:border-cyber-purple focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
            >
              <option value="All">All Difficulties</option>
              <option value="Easy">Easy</option>
              <option value="Medium">Medium</option>
              <option value="Hard">Hard</option>
            </select>

            {/* Status Filter */}
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-terminal-bg border border-cyber-purple/50 px-4 py-2 rounded text-cyber-purple focus:border-cyber-purple focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
            >
              <option value="All">All Statuses</option>
              <option value="Completed">Completed</option>
              <option value="In Progress">In Progress</option>
            </select>

            {/* Clear Filters */}
            <button
              onClick={() => {
                setSearchTerm('');
                setFilterDifficulty('All');
                setFilterStatus('All');
              }}
              className="bg-cyber-purple text-white px-4 py-2 rounded font-bold hover:bg-cyber-pink transition-colors"
            >
              Clear All
            </button>
          </div>
        </div>

        {/* Room Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredRooms.map((room) => (
            <MachineCardBase
              key={room.id}
              machine={room}
              provider="thm"
              isAdminMode={false}
              onViewWriteup={(machine) => handleViewWriteup(machine as THMRoom)}
              onEdit={() => {}}
              onDelete={() => {}}
            />
          ))}
        </div>

        {filteredRooms.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-400 text-lg">No rooms found matching your criteria.</p>
          </div>
        )}


      </div>
    </Layout>
  );
};

export default TryHackMeRooms;
