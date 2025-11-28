'use client';

import { useState, useEffect, useMemo, Suspense } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import remarkGfm from 'remark-gfm';
import Layout from '@/components/Layout';
import ActiveCTF403 from '@/components/ActiveCTF403';
import { FaArrowLeft, FaCalendarAlt, FaTag, FaTrophy, FaExclamationCircle, FaDesktop, FaWindows, FaLinux, FaClock, FaChevronUp, FaServer, FaShieldAlt, FaCheckCircle, FaCopy, FaCheck, FaFlag } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import type { HTMLAttributes } from 'react';
import { parseTags } from '@/lib/utils';
import TableOfContents from '@/components/TableOfContents';
import CodeBlock from '@/components/CodeBlock';
import SimilarMachinesSkeleton from '@/components/SimilarMachinesSkeleton';
import GlitchText from '@/components/GlitchText';
import StatCard from '@/components/StatCard';
import { motion, AnimatePresence } from 'framer-motion';

interface CTFWriteup {
  id: string;
  title: string;
  slug: string;
  ctfName: string;
  category: string;
  difficulty: string;
  points: number;
  status: string;
  isActive?: boolean;
  dateCompleted: string | null;
  tags: string[] | string;
  writeup: string | null;
  summary: string | null;
  flag?: string;
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

export default function CTFWriteupPage() {
  const params = useParams();
  const slug = params?.slug as string;
  const [writeup, setWriteup] = useState<CTFWriteup | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verifiedWriteup, setVerifiedWriteup] = useState<CTFWriteup | null>(null);

  useEffect(() => {
    const fetchWriteup = async () => {
      try {
        setLoading(true);
        const response = await fetch('/api/admin/ctf-writeups-d1');
        const data = await response.json();
        
        if (response.ok) {
          const writeupsArray = Array.isArray(data) ? data : (data.writeups || []);
          const foundWriteup = writeupsArray.find((w: CTFWriteup) => w.slug === slug);
          
          if (foundWriteup) {
            setWriteup(foundWriteup);
          } else {
            setError('Writeup not found');
          }
        } else {
          setError('Failed to load writeup');
        }
      } catch (error) {
        console.error('Error fetching writeup:', error);
        setError('Failed to load writeup');
      } finally {
        setLoading(false);
      }
    };

    if (slug) {
      fetchWriteup();
    }
  }, [slug]);

  const handleAccessGranted = (writeupData: CTFWriteup) => {
    setVerifiedWriteup(writeupData);
  };

  // Always show access denied for active CTFs unless user has just verified
  if (writeup?.isActive && !verifiedWriteup) {
    return (
      <Layout>
        <ActiveCTF403
          writeupId={writeup.id}
          title={writeup.title}
          ctfName={writeup.ctfName}
          onAccessGranted={handleAccessGranted}
        />
      </Layout>
    );
  }

  const displayWriteup = verifiedWriteup || writeup;
  
  if (loading) {
    return (
      <div className="fixed inset-0 bg-terminal-bg flex items-center justify-center font-mono text-cyber-green">
        <div className="w-full max-w-2xl p-4">
          <p className="animate-fade-in">[ LOADING CHALLENGE DATA... ]</p>
          <span className="animate-pulse">_</span>
        </div>
      </div>
    );
  }

  if (!displayWriteup) {
    return (
      <Layout>
        <div className="py-8">
          <div className="flex items-center justify-center min-h-[400px]">
            <div className="text-red-400">Writeup not found</div>
          </div>
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout>
        <div className="py-8">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-red-400 mb-4">Error</h1>
            <p className="text-gray-400 mb-8">{error}</p>
            <button
              onClick={() => window.history.back()}
              className="bg-cyber-green text-black px-6 py-3 rounded-lg font-bold hover:bg-cyber-blue transition-colors"
            >
              <FaArrowLeft className="inline mr-2" />
              Go Back
            </button>
          </div>
        </div>
      </Layout>
    );
  }
  
  return <CTFWriteupContent writeup={displayWriteup} />;
}

function CTFWriteupContent({ writeup }: { writeup: CTFWriteup }) {
  const [showScroll, setShowScroll] = useState(false);
  const [booting, setBooting] = useState(true);
  const [bootSequence, setBootSequence] = useState<string[]>([]);
  const [flagVisible, setFlagVisible] = useState(false);
  const [allWriteups, setAllWriteups] = useState<CTFWriteup[]>([]);
  const [similarWriteups, setSimilarWriteups] = useState<CTFWriteup[]>([]);
  
  const tagsArray = useMemo(() => parseTags(writeup.tags), [writeup.tags]);
  const bootSteps = ["INITIALIZING INTERFACE...", "CONNECTING TO 0xJERRY'S LAB...", `AUTHENTICATING CHALLENGE: ${writeup.title.toUpperCase()}...`, "SYSTEM DATA ACQUIRED.", "RENDERING UI..."];
  
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
  }, [writeup.id]);

  useEffect(() => {
    const fetchSimilarWriteups = async () => {
      try {
        const response = await fetch('/api/admin/ctf-writeups-d1');
        const data = await response.json();
        if (response.ok) {
          const writeupsArray = Array.isArray(data) ? data : (data.writeups || []);
          setAllWriteups(writeupsArray);
          
          // Find other challenges from the same CTF
          const otherChallenges = writeupsArray
            .filter((w: CTFWriteup) => w.id !== writeup.id && w.ctfName === writeup.ctfName)
            .slice(0, 3);
          setSimilarWriteups(otherChallenges);
        }
      } catch (error) {
        console.error('Error fetching similar writeups:', error);
      }
    };
    
    fetchSimilarWriteups();
  }, [writeup.id, tagsArray]);

  const scrollTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    const tocContainer = document.getElementById('toc-container');
    if (tocContainer) {
      tocContainer.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const getCategoryIcon = () => {
    const category = writeup.category.toLowerCase();
    if (category.includes('web')) return <FaDesktop />;
    if (category.includes('crypto')) return <FaShieldAlt />;
    if (category.includes('pwn')) return <FaServer />;
    return <FaFlag />;
  };

  const getDifficultyColor = () => {
    switch (writeup.difficulty.toLowerCase()) {
      case 'easy': return 'text-green-400 border-green-400';
      case 'medium': return 'text-yellow-400 border-yellow-400';
      case 'hard': return 'text-red-400 border-red-400';
      case 'insane': return 'text-purple-400 border-purple-400';
      default: return 'text-gray-400 border-gray-400';
    }
  };

  const getStatusColor = () => {
    switch (writeup.status.toLowerCase()) {
      case 'completed': return 'bg-green-500/20 text-green-400 border-green-400';
      case 'in progress': return 'bg-yellow-500/20 text-yellow-400 border-yellow-400';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-400';
    }
  };

  const copyFlag = () => {
    if (writeup?.flag) {
      navigator.clipboard.writeText(writeup.flag);
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
        <motion.nav initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }} className="flex items-center space-x-2 text-sm mb-8 overflow-x-auto">
          <Link href="/ctf" className="text-cyber-blue hover:text-cyber-green transition-colors whitespace-nowrap flex items-center gap-2"><FaArrowLeft /> Back to CTF</Link>
          <span className="text-gray-500">/</span>
          <span className="text-gray-400 truncate">{writeup.title}</span>
        </motion.nav>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3, duration: 0.5 }} className="mb-8 md:mb-12">
          <GlitchText text={writeup.title} className="text-4xl md:text-6xl font-cyber font-bold" />
          <p className="text-cyber-blue mt-2 text-lg">CHALLENGE ANALYSIS // {writeup.ctfName} :: {writeup.id}</p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <motion.aside initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5, duration: 0.5 }} className="lg:col-span-2">
            <div className="sticky top-24 space-y-6">
              <div className="backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4" style={{ animation: 'panelLoad 0.6s ease-out forwards' }}>
                <h3 className="font-cyber text-xl text-cyber-green mb-4">CHALLENGE VITALS</h3>
                <div className="space-y-3">
                  <StatCard icon={getCategoryIcon()} label="Category" value={writeup.category} delay={0} />
                  <StatCard icon={<FaShieldAlt />} label="Difficulty" value={<span className={getDifficultyColor().split(' ')[0]}>{writeup.difficulty}</span>} delay={0.1} />
                  <StatCard icon={<FaCheckCircle />} label="Status" value={<span className={`px-2 py-0.5 rounded text-xs font-semibold ${getStatusColor()}`}>{writeup.status}</span>} delay={0.2} />
                  {writeup.points > 0 && <StatCard icon={<FaTrophy />} label="Points" value={writeup.points} delay={0.3} />}
                  {writeup.dateCompleted && <StatCard icon={<FaCalendarAlt />} label="Completed" value={new Date(writeup.dateCompleted).toLocaleDateString()} delay={0.4} />}
                </div>
              </div>

              <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4" style={{ animation: 'panelLoad 0.8s ease-out forwards' }}>
                <h3 className="font-cyber text-xl text-cyber-purple mb-4">ATTACK VECTORS</h3>
                <div className="flex flex-wrap gap-2">
                  {tagsArray.map((tag, index) => (
                    <motion.span key={index} initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 1 + index * 0.1 }} className="px-2 py-1 bg-cyber-purple/20 text-cyber-purple text-xs rounded-full border border-cyber-purple/30 break-all">{tag}</motion.span>
                  ))}
                </div>
              </div>

              {writeup.flag && writeup.status === 'Completed' && (
                <div className="rounded-2xl backdrop-blur-sm bg-green-900/20 border border-green-500/50 p-4" style={{ animation: 'panelLoad 1.0s ease-out forwards' }}>
                  <h3 className="font-cyber text-xl text-green-400 mb-4">FLAG</h3>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-green-400 font-semibold text-sm">Challenge Flag:</span>
                    <button onClick={() => setFlagVisible(!flagVisible)} className="text-green-400 hover:text-green-300 text-sm">
                      {flagVisible ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  {flagVisible && (
                    <div className="flex items-center bg-black/30 p-3 rounded">
                      <code className="text-green-400 font-mono flex-1 text-sm break-all">{writeup.flag}</code>
                      <button onClick={copyFlag} className="ml-3 text-gray-400 hover:text-white" title="Copy flag"><FaCopy /></button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </motion.aside>

          <motion.main initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6, duration: 0.5 }} className="lg:col-span-8">
            <div className={`rounded-2xl p-4 md:p-6 lg:p-8 min-h-[60vh] ${writeup.writeup && writeup.writeup.length > 10000 ? 'backdrop-blur-lg bg-black/80 light:bg-white/85 border border-white/20' : 'backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10'}`} style={{ animation: 'panelLoad 1s ease-out forwards' }}>
              <h2 className="text-2xl font-bold text-cyber-green mb-6 font-cyber">CHALLENGE BRIEFING // WRITEUP</h2>
              <div className="markdown-content text-gray-300 leading-relaxed text-base">
                {writeup.writeup ? (
                  <ReactMarkdown 
                    remarkPlugins={[remarkGfm]} 
                    components={{
                      code: ({ node, inline, className, children, ...props }: any) => {
                        if (!inline) {
                          return <CodeBlock className={className}>{String(children).replace(/\n$/, '')}</CodeBlock>;
                        }
                        return (
                          <code 
                            className="bg-terminal-bg/60 text-cyber-green px-1.5 py-0.5 rounded font-mono text-sm border border-cyber-green/20 mx-0.5" 
                            style={{ display: 'inline', whiteSpace: 'nowrap', verticalAlign: 'baseline' }}
                            {...props}
                          >
                            {children}
                          </code>
                        );
                      },
                      pre: PreBlock,
                      h1: ({ children, ...props }) => {
                        const id = children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
                        return (
                          <h1 
                            id={id}
                            className="text-3xl font-cyber font-bold text-cyber-green mt-12 mb-6 border-b-2 border-cyber-green/50 pb-3 first:mt-0" 
                            {...props}
                          >
                            {children}
                          </h1>
                        );
                      },
                      h2: ({ children, ...props }) => {
                        const id = children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
                        return (
                          <h2 
                            id={id}
                            className="text-2xl font-cyber font-bold text-cyber-blue mt-10 mb-4 border-l-4 border-cyber-blue pl-4" 
                            {...props}
                          >
                            {children}
                          </h2>
                        );
                      },
                      h3: ({ children, ...props }) => {
                        const id = children?.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
                        return (
                          <h3 
                            id={id}
                            className="text-xl font-cyber font-bold text-cyber-purple mt-8 mb-3" 
                            {...props}
                          >
                            {children}
                          </h3>
                        );
                      },
                      p: ({ children, ...props }) => (
                        <p className="text-gray-300 leading-7 mb-4 text-justify" {...props}>
                          {children}
                        </p>
                      ),
                      ul: ({ children, ...props }) => (
                        <ul className="space-y-2 mb-6 ml-4" {...props}>
                          {children}
                        </ul>
                      ),
                      ol: ({ children, ...props }) => (
                        <ol className="list-decimal space-y-2 mb-6 ml-6 text-gray-300" {...props}>
                          {children}
                        </ol>
                      ),
                      li: ({ children, ...props }) => (
                        <li className="text-gray-300 leading-6 relative pl-2 before:content-['▸'] before:absolute before:-left-4 before:text-cyber-green before:font-bold" {...props}>
                          {children}
                        </li>
                      ),
                      blockquote: ({ children, ...props }) => (
                        <blockquote className="border-l-4 border-cyber-purple bg-cyber-purple/10 p-4 my-6 rounded-r-lg italic" {...props}>
                          {children}
                        </blockquote>
                      ),
                      table: ({ children, ...props }) => (
                        <div className="overflow-x-auto my-8">
                          <table className="w-full border-collapse bg-terminal-bg/30 rounded-lg overflow-hidden" {...props}>
                            {children}
                          </table>
                        </div>
                      ),
                      thead: ({ children, ...props }) => (
                        <thead className="bg-cyber-green/20" {...props}>
                          {children}
                        </thead>
                      ),
                      th: ({ children, ...props }) => (
                        <th className="p-3 text-left font-bold text-cyber-green border-b-2 border-cyber-green/50" {...props}>
                          {children}
                        </th>
                      ),
                      td: ({ children, ...props }) => (
                        <td className="p-3 border-b border-gray-600/30 text-gray-300" {...props}>
                          {children}
                        </td>
                      ),
                      a: ({ children, ...props }) => (
                        <a className="text-cyber-blue hover:text-cyber-green transition-colors underline decoration-cyber-blue/50 hover:decoration-cyber-green break-words" {...props}>
                          {children}
                        </a>
                      ),
                      strong: ({ children, ...props }) => (
                        <strong className="text-cyber-green font-bold" {...props}>
                          {children}
                        </strong>
                      ),
                      em: ({ children, ...props }) => (
                        <em className="text-cyber-purple italic" {...props}>
                          {children}
                        </em>
                      ),
                      hr: ({ ...props }) => (
                        <hr className="border-0 h-px bg-gradient-to-r from-transparent via-cyber-green to-transparent my-8" {...props} />
                      ),
                    }}
                  >
                    {writeup.writeup}
                  </ReactMarkdown>
                ) : (
                  <div className="text-center py-12">
                    <FaExclamationCircle className="w-16 h-16 text-gray-500 mx-auto mb-4" />
                    <h3 className="text-xl font-semibold text-gray-400 mb-2">WRITEUP PENDING DECLASSIFICATION</h3>
                    <p className="text-gray-500">
                      {writeup.isActive ? 'This writeup is blocked while the challenge is still active.' : writeup.status === 'In Progress' ? 'This challenge writeup is still being processed.' : 'No writeup available for this challenge yet.'}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </motion.main>

          <motion.aside initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5, duration: 0.5 }} className="lg:col-span-2">
            <div className="sticky top-24">
              {writeup.writeup && <TableOfContents content={writeup.writeup} />}
              <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 mt-6" style={{ animation: 'panelLoad 1.2s ease-out forwards' }}>
                <h3 className="font-cyber text-xl text-cyber-blue mb-4">OTHER CHALLENGES</h3>
                <Suspense fallback={<SimilarMachinesSkeleton />}>
                  {similarWriteups.length > 0 ? (
                    <div className="space-y-3">
                      {similarWriteups.map((similarWriteup, index) => (
                        <motion.div key={similarWriteup.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 1.2 + index * 0.15 }}>
                          <Link href={`/ctf/${similarWriteup.slug}`} className="block bg-terminal-bg/50 border border-cyber-blue/20 rounded-lg p-3 hover:border-cyber-blue hover:bg-cyber-blue/10 transition-all group">
                            <h4 className="font-semibold text-white mb-1 group-hover:text-cyber-blue transition-colors break-words text-sm">{similarWriteup.title}</h4>
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-gray-400 truncate">{similarWriteup.ctfName}</span>
                              <span className={getDifficultyColor().split(' ')[0]}>{similarWriteup.difficulty}</span>
                            </div>
                          </Link>
                        </motion.div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <FaExclamationCircle className="w-8 h-8 text-gray-500 mx-auto mb-2" />
                      <p className="text-gray-500 text-sm">No other challenges from this CTF.</p>
                    </div>
                  )}
                </Suspense>
              </div>
            </div>
          </motion.aside>
        </div>

        <AnimatePresence>
          {showScroll && (
            <motion.button onClick={scrollTop} className="fixed bottom-8 right-8 bg-cyber-green text-black p-3 rounded-full shadow-lg hover:bg-cyber-green-dark transition-colors z-50" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 20 }}>
              <FaChevronUp className="w-5 h-5" />
            </motion.button>
          )}
        </AnimatePresence>
      </div>
    </Layout>
  );
}