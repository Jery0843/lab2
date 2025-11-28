'use client';

import { useState, useEffect, useMemo, Suspense } from 'react';
import Link from 'next/link';
import remarkGfm from 'remark-gfm';
import Layout from '@/components/Layout';
import { FaArrowLeft, FaCalendarAlt, FaTag, FaTrophy, FaExclamationCircle, FaGraduationCap, FaClock, FaChevronUp, FaShieldAlt, FaCheckCircle, FaCopy, FaCheck, FaEdit, FaSave, FaTimes, FaExternalLinkAlt } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import type { HTMLAttributes } from 'react';
import { parseTags } from '@/lib/utils';
import TableOfContents from '@/components/TableOfContents';
import CodeBlock from '@/components/CodeBlock';
import SimilarMachinesSkeleton from '@/components/SimilarMachinesSkeleton';
import GlitchText from '@/components/GlitchText';
import StatCard from '@/components/StatCard';
import { motion, AnimatePresence } from 'framer-motion';

interface THMRoom {
  id: string;
  name?: string;
  title: string;
  slug: string;
  difficulty: string;
  status: string;
  tags: string[] | string; // Can be either array or string from database
  writeup: string | null;
  createdAt: string;
  updatedAt: string;
  url: string;
  roomCode?: string;
  room_code?: string;
  points: number;
  dateCompleted: string | null;
}

interface THMRoomPageProps {
  room: THMRoom;
}

function PreBlock(props: HTMLAttributes<HTMLPreElement>) {
  const { children } = props as any;
  const [isCopied, setIsCopied] = useState(false);
  const codeString = children?.props?.children;
  const handleCopy = () => {
    if (typeof codeString === 'string') {
      navigator.clipboard.writeText(codeString);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    }
  };
  return (
    <div className="relative group my-4">
      <button onClick={handleCopy} className="absolute top-2 right-2 p-1.5 bg-gray-700 rounded-md text-gray-300 hover:bg-gray-600 opacity-0 group-hover:opacity-100 transition-opacity z-10">
        {isCopied ? <FaCheck className="text-green-400" /> : <FaCopy />}
      </button>
      <pre className="bg-terminal-bg p-4 rounded border border-cyber-purple/30 overflow-x-auto text-sm" {...props}>{children}</pre>
    </div>
  );
}

const THMRoomPage = ({ room }: THMRoomPageProps) => {
  const [relatedRooms] = useState<THMRoom[]>([]);
  const [showScroll, setShowScroll] = useState(false);
  const [booting, setBooting] = useState(true);
  const [bootSequence, setBootSequence] = useState<string[]>([]);
  
  // Handle both dateCompleted (camelCase) and date_completed (snake_case) from database
  const dateCompleted = room.dateCompleted || (room as any).date_completed || '';
  
  // Handle tags - ensure it's an array
  const tagsArray = useMemo(() => parseTags(room.tags), [room.tags]);
  const bootSteps = useMemo(() => [
    "INITIALIZING INTERFACE...", 
    "CONNECTING TO 0xJERRY'S LAB...", 
    `AUTHENTICATING ROOM: ${(room.name || room.title)?.toUpperCase() || 'LOADING'}...`, 
    "SYSTEM DATA ACQUIRED.", 
    "RENDERING UI..."
  ], [room.name, room.title]);

  // Effect for scroll-to-top button
  useEffect(() => {
    const checkScrollTop = () => {
      if (!showScroll && window.pageYOffset > 400) {
        setShowScroll(true);
      } else if (showScroll && window.pageYOffset <= 400) {
        setShowScroll(false);
      }
    };
    window.addEventListener('scroll', checkScrollTop);
    return () => window.removeEventListener('scroll', checkScrollTop);
  }, [showScroll]);

  // Boot sequence effect
  useEffect(() => {
    setBooting(true);
    setBootSequence([]);
    const timers: NodeJS.Timeout[] = [];
    bootSteps.forEach((step, index) => {
      timers.push(setTimeout(() => {
        setBootSequence(prev => [...prev, step]);
        if (index === bootSteps.length - 1) {
          setTimeout(() => setBooting(false), 500);
        }
      }, index * 400));
    });
    return () => timers.forEach(clearTimeout);
  }, [bootSteps, room.id]);



  const scrollTop = () => {
    // Scroll main window to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
    // Scroll the Table of Contents container to its top
    const tocContainer = document.getElementById('toc-container');
    if (tocContainer) {
      tocContainer.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const getDifficultyColor = () => {
    switch (room.difficulty.toLowerCase()) {
      case 'easy':
        return 'text-green-400 border-green-400';
      case 'medium':
        return 'text-yellow-400 border-yellow-400';
      case 'hard':
        return 'text-red-400 border-red-400';
      case 'insane':
        return 'text-purple-400 border-purple-400';
      default:
        return 'text-gray-400 border-gray-400';
    }
  };

  const getStatusColor = () => {
    switch (room.status.toLowerCase()) {
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-400';
      case 'in progress':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-400';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-400';
    }
  };



  if (booting) {
    return (
      <div className="fixed inset-0 bg-terminal-bg flex items-center justify-center font-mono text-cyber-purple">
        <div className="w-full max-w-2xl p-4">
          {bootSequence.map((step, index) => (
            <p key={index} className="animate-fade-in">[ {step} ]</p>
          ))}
          <span className="animate-pulse">_</span>
        </div>
      </div>
    );
  }

  return (
    <Layout>
      <div className="py-4 md:py-8 px-4 md:px-6 lg:px-8 max-w-screen-xl mx-auto">
        {/* Breadcrumb */}
        <motion.nav initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }} className="flex items-center space-x-2 text-sm mb-8 overflow-x-auto">
          <Link href="/machines/thm" className="text-cyber-purple hover:text-cyber-pink transition-colors whitespace-nowrap flex items-center gap-2"><FaArrowLeft /> Back to THM</Link>
          <span className="text-gray-500">/</span>
          <span className="text-gray-400 truncate">{room.title}</span>
        </motion.nav>

        {/* Room Header */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3, duration: 0.5 }} className="mb-8 md:mb-12">
          <GlitchText text={room.name || room.title} className="text-4xl md:text-6xl font-cyber font-bold text-cyber-purple" />
          <p className="text-cyber-blue mt-2 text-lg">LEARNING LAB // THM :: {room.name || room.title}</p>
        </motion.div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">

          {/* Left Sidebar: Vitals */}
          <motion.aside 
            initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5, duration: 0.5 }}
            className="lg:col-span-2"
          >
            <div className="sticky top-24 space-y-6">
              {/* System Vitals */}
              <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4" style={{ animation: 'panelLoad 0.6s ease-out forwards' }}>
                <h3 className="font-cyber text-xl text-cyber-purple mb-4">ROOM VITALS</h3>
                <div className="space-y-2">
                  <div className="bg-terminal-bg/50 border border-cyber-purple/20 p-3 rounded-lg">
                    <div className="text-cyber-purple text-lg mb-1"><FaGraduationCap /></div>
                    <div className="text-xs text-gray-400 uppercase tracking-wider mb-1">Platform</div>
                    <div className="font-bold text-sm text-white break-words">TryHackMe</div>
                  </div>
                  <div className="bg-terminal-bg/50 border border-cyber-purple/20 p-3 rounded-lg">
                    <div className="text-cyber-purple text-lg mb-1"><FaShieldAlt /></div>
                    <div className="text-xs text-gray-400 uppercase tracking-wider mb-1">Difficulty</div>
                    <div className={`font-bold text-sm break-words ${getDifficultyColor().split(' ')[0]}`}>{room.difficulty}</div>
                  </div>
                  <div className="bg-terminal-bg/50 border border-cyber-purple/20 p-3 rounded-lg">
                    <div className="text-cyber-purple text-lg mb-1"><FaCheckCircle /></div>
                    <div className="text-xs text-gray-400 uppercase tracking-wider mb-1">Status</div>
                    <div className="font-bold text-sm text-white break-words">{room.status}</div>
                  </div>

                  {dateCompleted && (
                    <div className="bg-terminal-bg/50 border border-cyber-purple/20 p-3 rounded-lg">
                      <div className="text-cyber-purple text-lg mb-1"><FaCalendarAlt /></div>
                      <div className="text-xs text-gray-400 uppercase tracking-wider mb-1">Completed</div>
                      <div className="font-bold text-sm text-white break-words">{new Date(dateCompleted).toLocaleDateString()}</div>
                    </div>
                  )}
                </div>
              </div>

              {/* Tags */}
              <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4" style={{ animation: 'panelLoad 0.8s ease-out forwards' }}>
                <h3 className="font-cyber text-xl text-cyber-purple mb-4">LEARNING VECTORS</h3>
                <div className="flex flex-wrap gap-2">
                  {tagsArray.map((tag, index) => (
                    <motion.span key={index} initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 1 + index * 0.1 }} className="px-3 py-1 bg-cyber-purple/20 text-cyber-purple text-sm rounded-full border border-cyber-purple/30">{tag}</motion.span>
                  ))}
                </div>
              </div>

              {/* Room Code */}
              {(room.roomCode || room.room_code) && (
                <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4" style={{ animation: 'panelLoad 0.9s ease-out forwards' }}>
                  <h3 className="font-cyber text-xl text-cyber-purple mb-4">ROOM CODE</h3>
                  <div className="bg-terminal-bg/50 border border-cyber-purple/20 p-3 rounded-lg">
                    <div className="font-mono text-cyber-purple text-lg break-all">{room.roomCode || room.room_code}</div>
                  </div>
                </div>
              )}

              {/* External Link */}
              {room.url && (
                <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4" style={{ animation: 'panelLoad 1.0s ease-out forwards' }}>
                  <h3 className="font-cyber text-xl text-cyber-blue mb-4">EXTERNAL ACCESS</h3>
                  <a
                    href={room.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 px-4 py-2 bg-cyber-purple text-white rounded-lg font-bold hover:bg-cyber-pink transition-colors"
                  >
                    <FaExternalLinkAlt />
                    <span>Open on THM</span>
                  </a>
                </div>
              )}
            </div>
          </motion.aside>

          {/* Center Column: Writeup */}
          <motion.main 
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6, duration: 0.5 }}
            className="lg:col-span-8"
          >
            <div className={`rounded-2xl p-4 md:p-6 lg:p-8 min-h-[60vh] prose prose-invert max-w-none text-gray-300 leading-relaxed text-sm md:text-base prose-p:leading-relaxed prose-headings:font-cyber prose-a:text-cyber-purple hover:prose-a:text-cyber-pink prose-strong:text-cyber-purple prose-headings:text-cyber-purple prose-blockquote:border-cyber-purple prose-blockquote:bg-cyber-purple/10 prose-blockquote:p-4 prose-blockquote:rounded-md prose-li:marker:text-cyber-purple prose-table:w-full prose-table:my-6 prose-table:border-collapse prose-thead:border-b-2 prose-thead:border-cyber-purple prose-th:p-3 prose-th:text-left prose-th:font-bold prose-th:text-cyber-purple prose-tbody>tr:border-b prose-tbody>tr:border-cyber-purple/20 prose-tbody>tr:last-child:border-0 prose-td:p-3 prose-td:align-top ${room.writeup && room.writeup.length > 10000 ? 'backdrop-blur-lg bg-black/80 light:bg-white/85 border border-white/20' : 'backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10'}`} style={{ animation: 'panelLoad 1s ease-out forwards' }}>
              <h2 className="text-2xl font-bold text-cyber-purple mb-6 font-cyber">LEARNING BRIEFING // WRITEUP</h2>
              {room.writeup ? (
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={{
                  code: (props: any) => {
                    const { children, className, inline, ...rest } = props;
                    const match = /language-(\w+)/.exec(className || '');
                    // It's a block of code
                    if (!inline) {
                      // It has a language (e.g., ```bash)
                      return <CodeBlock className={className}>{String(children).replace(/\n$/, '')}</CodeBlock>;
                    }
                    // It's an inline code snippet
                    return (
                      <code className={`bg-terminal-bg/50 p-1 rounded text-cyber-purple border border-cyber-purple/30 text-xs md:text-sm ${className || ''}`} {...rest}>{children}</code>
                    )
                  },
                  pre: PreBlock,
                  h1: ({ node, ...props }) => <h1 id={props.children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '')} className="text-2xl font-bold text-cyber-purple mt-8 mb-4 border-b border-cyber-purple/30 pb-2" {...props} />,
                  h2: ({ node, ...props }) => <h2 id={props.children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '')} className="text-xl font-bold text-cyber-purple mt-6 mb-3" {...props} />,
                  h3: ({ node, ...props }) => <h3 id={props.children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '')} className="text-lg font-bold text-cyber-purple mt-4 mb-2" {...props} />,
                  ul: ({ node, ...props }) => <ul className="list-disc list-outside" {...props} />,
                  ol: ({ node, ...props }) => <ol className="list-decimal list-outside" {...props} />,
                  a: ({ node, ...props }) => <a className="break-words" {...props} />,
                }}>{room.writeup}</ReactMarkdown>
              ) : (
                <div className="text-center py-12">
                  <FaExclamationCircle className="w-16 h-16 text-gray-500 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-400 mb-2">WRITEUP PENDING DECLASSIFICATION</h3>
                  <p className="text-gray-500">This room&apos;s data is still being processed.</p>
                </div>
              )}
            </div>
          </motion.main>

          {/* Right Sidebar: Intel & Navigation */}
          <motion.aside 
            initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5, duration: 0.5 }}
            className="lg:col-span-2"
          >
            <div className="sticky top-24">
              {/* Table of Contents */}
              {room.writeup && <TableOfContents content={room.writeup} />}


            </div>
          </motion.aside>

        </div>



        {/* Scroll to Top Button */}
        <AnimatePresence>
          {showScroll && (
            <motion.button
              onClick={scrollTop}
              className="fixed bottom-8 right-8 bg-cyber-purple text-white p-3 rounded-full shadow-lg hover:bg-cyber-pink transition-colors z-50"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
            >
              <FaChevronUp className="w-5 h-5" />
            </motion.button>
          )}
        </AnimatePresence>
      </div>
    </Layout>
  );
};

export default THMRoomPage;
