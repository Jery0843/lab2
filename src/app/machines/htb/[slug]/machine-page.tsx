'use client';

import { useState, useEffect, useMemo, Suspense } from 'react';
import Link from 'next/link';
import remarkGfm from 'remark-gfm'; 
import Layout from '@/components/Layout';
import { FaArrowLeft, FaCalendarAlt, FaTag, FaTrophy, FaExclamationCircle, FaDesktop, FaWindows, FaLinux, FaClock, FaChevronUp, FaServer, FaShieldAlt, FaCheckCircle, FaCopy, FaCheck } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import type { HTMLAttributes } from 'react';
import { parseTags } from '@/lib/utils';
import TableOfContents from '@/components/TableOfContents';
import CodeBlock from '@/components/CodeBlock';
import SimilarMachinesSkeleton from '@/components/SimilarMachinesSkeleton';
import GlitchText from '@/components/GlitchText';
import StatCard from '@/components/StatCard';
import { motion, AnimatePresence } from 'framer-motion';
import ActiveMachine403 from '@/components/ActiveMachine403';

interface Machine {
  id: string;
  name: string;
  os: string;
  difficulty: string;
  status: string;
  is_active?: number | boolean;
  summary?: string | null;
  dateCompleted: string | null;
  tags: string[] | string;
  writeup: string | null;
}

interface MachinePageProps {
  machine: Machine;
  initialRelatedMachines: Machine[];
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
      <pre className="bg-terminal-bg p-4 rounded border border-cyber-green/30 overflow-x-auto text-sm" {...props}>{children}</pre>
    </div>
  );
}

export default function MachinePage({ machine, initialRelatedMachines }: MachinePageProps) {
  const [verifiedWriteup, setVerifiedWriteup] = useState<string | null>(null);
  
  // Decide gating first, but render via child component to avoid conditional hooks
  const isActiveFlag = typeof machine.is_active === 'number' ? machine.is_active === 1 : Boolean((machine as any).is_active);
  const statusLower = (machine.status || '').toLowerCase();
  const fallbackActive = !('is_active' in (machine as any)) && statusLower !== 'completed' && statusLower !== 'retired';
  const isActiveGate = isActiveFlag === true || fallbackActive;

  const handlePasswordVerified = (writeup: string) => {
    setVerifiedWriteup(writeup);
  };

  if (isActiveGate && !verifiedWriteup) {
    return (
      <ActiveMachine403 
        machineName={machine.name} 
        summary={machine.summary || null}
        machineId={machine.id}
        onPasswordVerified={handlePasswordVerified}
      />
    );
  }

  // If password was verified, create a modified machine object with the writeup
  const displayMachine = verifiedWriteup ? { ...machine, writeup: verifiedWriteup } : machine;
  
  return <MachineContent machine={displayMachine} initialRelatedMachines={initialRelatedMachines} />;
}

function MachineContent({ machine, initialRelatedMachines }: MachinePageProps) {
  const [relatedMachines] = useState<Machine[]>(initialRelatedMachines);
  const [showScroll, setShowScroll] = useState(false);
  const [booting, setBooting] = useState(true);
  const [bootSequence, setBootSequence] = useState<string[]>([]);
  
  // Handle tags - ensure it's an array
  const tagsArray = useMemo(() => parseTags(machine.tags), [machine.tags]);
  const bootSteps = ["INITIALIZING INTERFACE...", "CONNECTING TO 0xJERRY'S LAB...", `AUTHENTICATING MACHINE: ${machine.name.toUpperCase()}...`, "SYSTEM DATA ACQUIRED.", "RENDERING UI..."];
  
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
  }, [machine.id]);

  const scrollTop = () => {
    // Scroll main window to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
    // Scroll the Table of Contents container to its top
    const tocContainer = document.getElementById('toc-container');
    if (tocContainer) {
      tocContainer.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const getOSIcon = () => {
    const os = machine.os.toLowerCase();
    if (os.includes('windows')) return <FaWindows />;
    if (os.includes('linux')) return <FaLinux />;
    return <FaServer />;
  };

  const getDifficultyColor = () => {
    switch (machine.difficulty.toLowerCase()) {
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
    switch (machine.status.toLowerCase()) {
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
      <div className="fixed inset-0 bg-terminal-bg flex items-center justify-center font-mono text-cyber-green">
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
          <Link href="/machines/htb" className="text-cyber-blue hover:text-cyber-green transition-colors whitespace-nowrap flex items-center gap-2"><FaArrowLeft /> Back to HTB</Link>
          <span className="text-gray-500">/</span>
          <span className="text-gray-400 truncate">{machine.name}</span>
        </motion.nav>

        {/* Machine Header */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3, duration: 0.5 }} className="mb-8 md:mb-12">
          <GlitchText text={machine.name} className="text-4xl md:text-6xl font-cyber font-bold" />
          <p className="text-cyber-blue mt-2 text-lg">SYSTEM ANALYSIS // HTB :: {machine.id}</p>
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
                <h3 className="font-cyber text-xl text-cyber-green mb-4">SYSTEM VITALS</h3>
                <div className="space-y-3">
                  <StatCard icon={getOSIcon()} label="Operating System" value={machine.os} delay={0} />
                  <StatCard icon={<FaShieldAlt />} label="Difficulty" value={<span className={getDifficultyColor().split(' ')[0]}>{machine.difficulty}</span>} delay={0.1} />
                  <StatCard icon={<FaCheckCircle />} label="Status" value={<span className={`px-2 py-0.5 rounded text-xs font-semibold ${getStatusColor()}`}>{machine.status}</span>} delay={0.2} />
                  {machine.dateCompleted && <StatCard icon={<FaCalendarAlt />} label="Completed" value={new Date(machine.dateCompleted).toLocaleDateString()} delay={0.3} />}
                </div>
              </div>

              {/* Tags */}
              <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4" style={{ animation: 'panelLoad 0.8s ease-out forwards' }}>
                <h3 className="font-cyber text-xl text-cyber-purple mb-4">THREAT VECTORS</h3>
                <div className="flex flex-wrap gap-2">
                  {tagsArray.map((tag, index) => (
                    <motion.span key={index} initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 1 + index * 0.1 }} className="px-3 py-1 bg-cyber-purple/20 text-cyber-purple text-sm rounded-full border border-cyber-purple/30">{tag}</motion.span>
                  ))}
                </div>
              </div>
            </div>
          </motion.aside>

          {/* Center Column: Writeup */}
          <motion.main 
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6, duration: 0.5 }}
            className="lg:col-span-8"
          >
            <div className={`rounded-2xl p-4 md:p-6 lg:p-8 min-h-[60vh] prose prose-invert max-w-none text-gray-300 leading-relaxed text-sm md:text-base prose-p:leading-relaxed prose-headings:font-cyber prose-a:text-cyber-blue hover:prose-a:text-cyber-green prose-strong:text-cyber-green prose-headings:text-cyber-blue prose-blockquote:border-cyber-purple prose-blockquote:bg-cyber-purple/10 prose-blockquote:p-4 prose-blockquote:rounded-md prose-li:marker:text-cyber-green prose-table:w-full prose-table:my-6 prose-table:border-collapse prose-thead:border-b-2 prose-thead:border-cyber-green prose-th:p-3 prose-th:text-left prose-th:font-bold prose-th:text-cyber-green prose-tbody>tr:border-b prose-tbody>tr:border-cyber-green/20 prose-tbody>tr:last-child:border-0 prose-td:p-3 prose-td:align-top ${machine.writeup && machine.writeup.length > 10000 ? 'backdrop-blur-lg bg-black/80 light:bg-white/85 border border-white/20' : 'backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10'}`} style={{ animation: 'panelLoad 1s ease-out forwards' }}>
              <h2 className="text-2xl font-bold text-cyber-green mb-6 font-cyber">MISSION BRIEFING // WRITEUP</h2>
              {machine.writeup ? (
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
                  h1: ({ node, ...props }) => <h1 id={props.children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '')} className="text-2xl font-bold text-cyber-green mt-8 mb-4 border-b border-cyber-green/30 pb-2" {...props} />,
                  h2: ({ node, ...props }) => <h2 id={props.children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '')} className="text-xl font-bold text-cyber-blue mt-6 mb-3" {...props} />,
                  h3: ({ node, ...props }) => <h3 id={props.children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '')} className="text-lg font-bold text-cyber-purple mt-4 mb-2" {...props} />,
                  ul: ({ node, ...props }) => <ul className="list-disc list-outside" {...props} />,
                  ol: ({ node, ...props }) => <ol className="list-decimal list-outside" {...props} />,
                  a: ({ node, ...props }) => <a className="break-words" {...props} />,
                }}>{machine.writeup}</ReactMarkdown>
              ) : (
                <div className="text-center py-12">
                  <FaExclamationCircle className="w-16 h-16 text-gray-500 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-400 mb-2">WRITEUP PENDING DECLASSIFICATION</h3>
                  <p className="text-gray-500">This machine&apos;s data is still being processed.</p>
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
              {machine.writeup && <TableOfContents content={machine.writeup} />}

              {/* Similar Machines */}
              <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 mt-6" style={{ animation: 'panelLoad 1.2s ease-out forwards' }}>
                <h3 className="font-cyber text-xl text-cyber-blue mb-4">SIMILAR TARGETS</h3>
                <Suspense fallback={<SimilarMachinesSkeleton />}>
                  {relatedMachines.length > 0 ? (
                    <div className="space-y-3">
                      {relatedMachines.map((relatedMachine, index) => (
                        <motion.div key={relatedMachine.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.2 + index * 0.15 }}>
                          <Link href={`/machines/htb/${relatedMachine.id}`} className="block bg-terminal-bg/50 border border-cyber-blue/20 rounded-lg p-3 hover:border-cyber-blue hover:bg-cyber-blue/10 transition-all group">
                            <h4 className="font-semibold text-white mb-1 group-hover:text-cyber-blue transition-colors break-words">{relatedMachine.name}</h4>
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-gray-400 truncate">{relatedMachine.os}</span>
                              <span className={`whitespace-nowrap ${getDifficultyColor().split(' ')[0]}`}>{relatedMachine.difficulty}</span>
                            </div>
                          </Link>
                        </motion.div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <FaExclamationCircle className="w-8 h-8 text-gray-500 mx-auto mb-2" />
                      <p className="text-gray-500 text-sm">No similar targets found.</p>
                    </div>
                  )}
                </Suspense>
              </div>
            </div>
          </motion.aside>

        </div>

        {/* Scroll to Top Button */}
        <AnimatePresence>
          {showScroll && (
            <motion.button
              onClick={scrollTop}
              className="fixed bottom-8 right-8 bg-cyber-green text-black p-3 rounded-full shadow-lg hover:bg-cyber-green-dark transition-colors z-50"
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
}
