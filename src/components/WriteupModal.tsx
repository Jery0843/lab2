'use client';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { FaTimes } from 'react-icons/fa';

interface Machine {
  id: string;
  name: string;
  os: string;
  difficulty: string;
  status: string;
  dateCompleted: string | null;
  tags: string[];
  writeup: string | null;
}

interface WriteupModalProps {
  machine: Machine;
  onClose: () => void;
}

const WriteupModal = ({ machine, onClose }: WriteupModalProps) => {
  return (
    <div className="fixed inset-0 bg-black/90 flex items-center justify-center z-50 p-4 animate-fade-in">
      <div className="glass-panel rounded-lg max-w-4xl w-full h-full max-h-[90vh] mx-auto flex flex-col shadow-2xl">
        <div className="flex justify-between items-center p-6 border-b-2 border-cyber-green/50 bg-terminal-bg">
          <h2 className="text-2xl font-cyber font-bold text-cyber-green">
            {machine.name} Writeup
          </h2>
          <button onClick={onClose} className="text-gray-300 hover:text-cyber-green transition-colors p-2 rounded hover:bg-cyber-green/10">
            <FaTimes size={20} />
          </button>
        </div>

        <div className="prose prose-invert prose-lg p-8 overflow-y-auto flex-grow glass-panel text-gray-200
                        prose-headings:text-cyber-blue prose-headings:font-bold prose-headings:border-b prose-headings:border-cyber-blue/50 prose-headings:pb-3 prose-headings:mb-5
                        prose-strong:text-cyber-green prose-strong:font-bold
                        prose-a:text-cyber-blue hover:prose-a:text-cyber-green prose-a:transition-colors prose-a:underline
                        prose-blockquote:border-l-4 prose-blockquote:border-cyber-purple prose-blockquote:pl-6 prose-blockquote:text-gray-300 prose-blockquote:bg-gray-800/30 prose-blockquote:py-3
                        prose-pre:bg-terminal-bg prose-pre:border prose-pre:border-cyber-green/50 prose-pre:p-4 prose-pre:rounded-md prose-pre:text-sm 
                        prose-code:text-cyber-green prose-code:bg-terminal-bg prose-code:px-2 prose-code:py-1 prose-code:rounded prose-code:font-mono prose-code:before:content-none prose-code:after:content-none
                        prose-p:text-gray-200 prose-p:leading-loose
                        prose-li:text-gray-200 prose-li:my-2">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{machine.writeup || 'No writeup available.'}</ReactMarkdown>
        </div>

        <div className="p-4 border-t-2 border-cyber-green/30 text-center text-xs text-cyber-green bg-terminal-bg">
          [ END OF TRANSMISSION ]
        </div>
      </div>
    </div>
  );
};

export default WriteupModal;
