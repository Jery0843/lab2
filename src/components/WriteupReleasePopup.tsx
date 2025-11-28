'use client';

import { useState, useEffect } from 'react';
import { FaTimes, FaExternalLinkAlt } from 'react-icons/fa';
import { motion, AnimatePresence } from 'framer-motion';

interface WriteupPopup {
  id: string;
  title: string;
  imageUrl: string;
  link: string;
  isActive: boolean;
  createdAt: string;
}

interface WriteupReleasePopupProps {
  onClose: () => void;
}

export default function WriteupReleasePopup({ onClose }: WriteupReleasePopupProps) {
  const [popup, setPopup] = useState<WriteupPopup | null>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const fetchPopup = async () => {
      try {
        const response = await fetch('/api/admin/writeup-popup');
        if (response.ok) {
          const data = await response.json();
          if (data.isActive) {
            setPopup(data);
            
            // Check if user has seen this popup today
            const lastSeen = localStorage.getItem('writeupPopupLastSeen');
            const today = new Date().toDateString();
            
            if (lastSeen !== today) {
              setTimeout(() => setIsVisible(true), 2000);
            }
          }
        }
      } catch (error) {
        console.error('Error fetching writeup popup:', error);
      }
    };

    fetchPopup();
  }, []);

  const handleClose = () => {
    setIsVisible(false);
    localStorage.setItem('writeupPopupLastSeen', new Date().toDateString());
    onClose();
  };

  const handleLinkClick = () => {
    if (popup?.link) {
      window.open(popup.link, '_blank');
      handleClose();
    }
  };

  if (!popup || !isVisible) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-[300]"
        onClick={handleClose}
      >
        <motion.div
          initial={{ scale: 0.8, opacity: 0, y: 50 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.8, opacity: 0, y: 50 }}
          transition={{ type: "spring", damping: 20, stiffness: 300 }}
          className="backdrop-blur-lg bg-white/10 border border-white/20 rounded-2xl max-w-md w-full mx-4 overflow-hidden shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="relative">
            <button
              onClick={handleClose}
              className="absolute top-4 right-4 z-10 text-white/80 hover:text-white bg-black/30 hover:bg-black/50 p-2 rounded-full transition-all"
            >
              <FaTimes size={16} />
            </button>
            
            {/* Image */}
            <div className="relative h-48 bg-gradient-to-br from-cyber-green/20 to-cyber-blue/20">
              {popup.imageUrl ? (
                <img
                  src={popup.imageUrl}
                  alt={popup.title}
                  className="w-full h-full object-cover"
                  onError={(e) => {
                    e.currentTarget.style.display = 'none';
                  }}
                />
              ) : (
                <div className="w-full h-full flex items-center justify-center">
                  <div className="text-6xl text-cyber-green/50">📝</div>
                </div>
              )}
              
              {/* Overlay gradient */}
              <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />
              
              {/* Badge */}
              <div className="absolute top-4 left-4">
                <span className="bg-green-500 text-white px-3 py-1 rounded-full text-xs font-bold animate-pulse">
                  NEW RELEASE
                </span>
              </div>
            </div>
          </div>

          {/* Content */}
          <div className="p-6">
            <h3 className="text-xl font-cyber font-bold text-white mb-4 leading-tight">
              {popup.title}
            </h3>
            
            <p className="text-gray-300 text-sm mb-6">
              Check out our latest writeup release! Click below to read the full analysis and walkthrough.
            </p>

            {/* Action Button */}
            <button
              onClick={handleLinkClick}
              className="w-full bg-green-500 hover:bg-blue-500 text-white py-3 px-6 rounded-xl font-bold transition-all duration-300 flex items-center justify-center space-x-2 shadow-lg border-2 border-green-500 hover:border-blue-500"
            >
              <span>Read Writeup</span>
              <FaExternalLinkAlt size={14} />
            </button>

            {/* Footer */}
            <div className="mt-4 text-center">
              <p className="text-xs text-gray-400">
                This popup shows once per day for new releases
              </p>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}