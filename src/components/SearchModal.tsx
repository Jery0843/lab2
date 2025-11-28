'use client';

import { useState } from 'react';
import { FaSearch, FaTimes, FaTools, FaNewspaper, FaComments, FaFlag } from 'react-icons/fa';
import { motion, AnimatePresence } from 'framer-motion';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SearchModal({ isOpen, onClose }: SearchModalProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSection, setSelectedSection] = useState('writeups');
  const [isSearching, setIsSearching] = useState(false);
  const [noResults, setNoResults] = useState(false);

  const handleSearch = async () => {
    if (searchTerm.trim() && !isSearching) {
      setIsSearching(true);
      if (selectedSection === 'writeups') {
        // Search across all writeup platforms
        try {
          const [htbRes, thmRes, ctfRes] = await Promise.all([
            fetch('/api/admin/htb-machines-d1'),
            fetch('/api/admin/thm-rooms-d1'),
            fetch('/api/admin/ctf-writeups-d1')
          ]);
          
          const [htbData, thmData, ctfData] = await Promise.all([
            htbRes.json(),
            thmRes.json(),
            ctfRes.json()
          ]);
          
          const searchLower = searchTerm.toLowerCase();
          
          // Search HTB machines
          const htbMachines = Array.isArray(htbData) ? htbData : htbData.machines || [];
          const htbMatch = htbMachines.find((m: any) => 
            (m.name || m.title || '').toLowerCase().includes(searchLower)
          );
          
          // Search THM rooms
          const thmRooms = Array.isArray(thmData) ? thmData : thmData.rooms || [];
          const thmMatch = thmRooms.find((r: any) => 
            (r.name || r.title || '').toLowerCase().includes(searchLower)
          );
          
          // Search CTF writeups
          const ctfWriteups = Array.isArray(ctfData) ? ctfData : ctfData.writeups || [];
          const ctfMatch = ctfWriteups.find((w: any) => 
            (w.title || '').toLowerCase().includes(searchLower) ||
            (w.ctf_name || w.ctfName || '').toLowerCase().includes(searchLower)
          );
          
          // Redirect to the first match found
          if (htbMatch && htbMatch.id) {
            window.location.href = `/machines/htb/${htbMatch.id}`;
          } else if (thmMatch && thmMatch.slug) {
            window.location.href = `/machines/thm/${thmMatch.slug}`;
          } else if (ctfMatch && ctfMatch.slug) {
            window.location.href = `/ctf/${ctfMatch.slug}`;
          } else {
            // No matches found, show no results
            setNoResults(true);
            setTimeout(() => setNoResults(false), 3000);
            setIsSearching(false);
            return; // Don't close modal
          }
        } catch (error) {
          console.error('Search error:', error);
          setNoResults(true);
          setTimeout(() => setNoResults(false), 3000);
          setIsSearching(false);
          return; // Don't close modal
        } finally {
          setIsSearching(false);
        }
      } else {
        window.location.href = `/${selectedSection}?search=${encodeURIComponent(searchTerm.trim())}`;
      }
      onClose();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
    if (e.key === 'Escape') {
      onClose();
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-[200]"
          onClick={onClose}
        >
          <motion.div 
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
            className="backdrop-blur-sm bg-white/10 border border-white/20 p-8 rounded-2xl max-w-lg w-full mx-4 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-2xl font-cyber font-bold text-cyber-green">
                SEARCH DATABASE
              </h3>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-cyber-green transition-colors p-2 hover:bg-white/10 rounded-lg"
              >
                <FaTimes size={20} />
              </button>
            </div>

            <div className="relative mb-6">
              <FaSearch className="absolute left-4 top-1/2 transform -translate-y-1/2 text-cyber-green/60" size={18} />
              <input
                type="text"
                placeholder="Search across all sections..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyDown={handleKeyDown}
                className="w-full bg-white/5 backdrop-blur-sm border border-white/20 pl-12 pr-4 py-4 rounded-xl text-white placeholder-gray-400 focus:border-cyber-green focus:outline-none focus:ring-2 focus:ring-cyber-green/20 transition-all"
                autoFocus
              />
            </div>

            <div className="mb-8">
              <p className="text-sm text-gray-300 mb-4 font-medium">Search Categories:</p>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={() => setSelectedSection('tools')}
                  className={`flex items-center space-x-3 p-4 rounded-xl border transition-all ${
                    selectedSection === 'tools'
                      ? 'bg-cyber-green/20 border-cyber-green text-cyber-green backdrop-blur-sm'
                      : 'border-white/20 text-gray-300 hover:border-cyber-green/60 hover:bg-white/5 backdrop-blur-sm'
                  }`}
                >
                  <FaTools size={16} />
                  <span className="font-medium">Tools</span>
                </button>
                <button
                  onClick={() => setSelectedSection('writeups')}
                  className={`flex items-center space-x-3 p-4 rounded-xl border transition-all ${
                    selectedSection === 'writeups'
                      ? 'bg-cyber-purple/20 border-cyber-purple text-cyber-purple backdrop-blur-sm'
                      : 'border-white/20 text-gray-300 hover:border-cyber-purple/60 hover:bg-white/5 backdrop-blur-sm'
                  }`}
                >
                  <FaFlag size={16} />
                  <span className="font-medium">All Writeups</span>
                </button>
                <button
                  onClick={() => setSelectedSection('news')}
                  className={`flex items-center space-x-3 p-4 rounded-xl border transition-all ${
                    selectedSection === 'news'
                      ? 'bg-cyber-blue/20 border-cyber-blue text-cyber-blue backdrop-blur-sm'
                      : 'border-white/20 text-gray-300 hover:border-cyber-blue/60 hover:bg-white/5 backdrop-blur-sm'
                  }`}
                >
                  <FaNewspaper size={16} />
                  <span className="font-medium">News</span>
                </button>
                <button
                  onClick={() => setSelectedSection('forums')}
                  className={`flex items-center space-x-3 p-4 rounded-xl border transition-all ${
                    selectedSection === 'forums'
                      ? 'bg-yellow-500/20 border-yellow-500 text-yellow-400 backdrop-blur-sm'
                      : 'border-white/20 text-gray-300 hover:border-yellow-500/60 hover:bg-white/5 backdrop-blur-sm'
                  }`}
                >
                  <FaComments size={16} />
                  <span className="font-medium">Forums</span>
                </button>
              </div>
            </div>

            <div className="flex space-x-4">
              <button
                onClick={handleSearch}
                disabled={!searchTerm.trim() || isSearching}
                className="flex-1 bg-cyber-green/90 text-white py-3 px-6 rounded-xl hover:bg-cyber-green transition-all font-bold disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-cyber-green/20 flex items-center justify-center"
              >
                {isSearching ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    SEARCHING...
                  </>
                ) : (
                  'SEARCH'
                )}
              </button>
              <button
                onClick={onClose}
                className="flex-1 bg-transparent border border-cyber-green/50 text-cyber-green py-3 px-6 rounded-xl hover:bg-cyber-green/10 hover:border-cyber-green transition-all backdrop-blur-sm font-bold"
              >
                CANCEL
              </button>
            </div>

            {noResults && (
              <div className="mb-4 p-3 bg-red-500/20 border border-red-500/50 rounded-xl text-center">
                <p className="text-red-400 font-medium">{`No writeups found for "${searchTerm}"`}</p>
              </div>
            )}

            <div className="mt-6 text-center">
              <p className="text-xs text-gray-400">
                Press <kbd className="px-2 py-1 bg-white/10 rounded text-xs">Enter</kbd> to search • <kbd className="px-2 py-1 bg-white/10 rounded text-xs">Esc</kbd> to close
              </p>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}