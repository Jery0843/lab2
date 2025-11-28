'use client';

import { useState, useEffect } from 'react';
import { FaTimes, FaPlus, FaTrash } from 'react-icons/fa';

interface Machine {
  id: string;
  name: string;
  os: string;
  difficulty: string;
  status: string;
  isActive?: boolean;
  summary?: string | null;
  dateCompleted: string | null;
  tags: string[];
  writeup: string | null;
}

interface AddMachineModalProps {
  machine: Machine | null;
  onSave: (machine: any) => void;
  onClose: () => void;
}

const AddMachineModal = ({ machine, onSave, onClose }: AddMachineModalProps) => {
  const [name, setName] = useState('');
  const [os, setOS] = useState('Linux');
  const [difficulty, setDifficulty] = useState('Easy');
  const [status, setStatus] = useState('In Progress');
  const [isActive, setIsActive] = useState(true);
  const [dateCompleted, setDateCompleted] = useState<string | null>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [writeup, setWriteup] = useState('');
  const [summary, setSummary] = useState('');

  useEffect(() => {
    if (machine) {
      setName(machine.name);
      setOS(machine.os);
      setDifficulty(machine.difficulty);
      setStatus(machine.status);
      setIsActive(machine.isActive ?? true);
      setDateCompleted(machine.dateCompleted);
      setTags(machine.tags);
      setWriteup(machine.writeup || '');
      setSummary(machine.summary || '');
    }
  }, [machine]);

  const handleAddTag = () => {
    if (tagInput && !tags.includes(tagInput)) {
      setTags([...tags, tagInput]);
      setTagInput('');
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    setTags(tags.filter(tag => tag !== tagToRemove));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave({
      id: machine?.id || name.toLowerCase().replace(/\s+/g, '-'),
      name,
      os,
      difficulty,
      status,
      isActive,
      summary: summary || null,
      dateCompleted: status === 'Completed' ? dateCompleted : null,
      tags,
      writeup
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/90 flex items-center justify-center z-50 p-4">
      <div className="glass-panel rounded-lg max-w-2xl w-full mx-auto animate-slide-up shadow-2xl">
        <form onSubmit={handleSubmit} className="p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-cyber font-bold" data-text={machine ? 'Edit Machine' : 'Add New Machine'}>
              {machine ? 'Edit Machine' : 'Add New Machine'}
            </h2>
            <button type="button" onClick={onClose} className="text-gray-400 hover:text-cyber-green">
              <FaTimes size={20} />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            {/* Left Column */}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">Machine Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Operating System</label>
                <select
                  value={os}
                  onChange={(e) => setOS(e.target.value)}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
                >
                  <option>Linux</option>
                  <option>Windows</option>
                  <option>Other</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Difficulty</label>
                <select
                  value={difficulty}
                  onChange={(e) => setDifficulty(e.target.value)}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
                >
                  <option>Easy</option>
                  <option>Medium</option>
                  <option>Hard</option>
                  <option>Insane</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Status</label>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none [&>option]:text-white [&>option]:bg-gray-800"
                >
                  <option>In Progress</option>
                  <option>Completed</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Active (machine is still live)</label>
                <div className="flex items-center gap-3">
                  <input
                    id="isActive"
                    type="checkbox"
                    checked={isActive}
                    onChange={(e) => setIsActive(e.target.checked)}
                    className="h-4 w-4 accent-cyber-green"
                  />
                  <label htmlFor="isActive" className="text-sm text-gray-300">Block write-up while active</label>
                </div>
              </div>
              {status === 'Completed' && (
                <div>
                  <label className="block text-sm font-semibold mb-2">Date Completed</label>
                  <input
                    type="date"
                    value={dateCompleted || ''}
                    onChange={(e) => setDateCompleted(e.target.value)}
                    className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none"
                  />
                </div>
              )}
            </div>

            {/* Right Column */}
            <div className="space-y-4">
            <div>
              <label className="block text-sm font-semibold mb-2">Summary (1–2 sentences for SEO)</label>
              <textarea
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                rows={3}
                maxLength={500}
                placeholder="Short, non-spoiler overview to help search engines."
                className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none"
              />
            </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Tags</label>
                <div className="flex items-center">
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleAddTag()}
                    placeholder="Add a tag and press Enter"
                    className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded-l text-cyber-green focus:border-cyber-green focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={handleAddTag}
                    className="bg-cyber-green text-black px-4 py-3 rounded-r hover:bg-cyber-blue transition-colors"
                  >
                    <FaPlus />
                  </button>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  {tags.map((tag) => (
                    <div key={tag} className="flex items-center bg-cyber-green/20 text-cyber-green text-sm px-2 py-1 rounded">
                      <span>{tag}</span>
                      <button type="button" onClick={() => handleRemoveTag(tag)} className="ml-2 text-red-400 hover:text-red-300">
                        <FaTrash size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Writeup (Markdown)</label>
                <textarea
                  value={writeup}
                  onChange={(e) => setWriteup(e.target.value)}
                  rows={12}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none font-mono"
                  placeholder="# Enumeration\n\n## Exploitation\n\n## Privilege Escalation..."
                />
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-4 pt-4 border-t border-cyber-green/30">
            <button type="button" onClick={onClose} className="px-6 py-2 rounded text-cyber-green hover:bg-gray-700 transition-colors">
              Cancel
            </button>
            <button type="submit" className="bg-cyber-green text-black px-6 py-2 rounded font-bold hover:bg-cyber-blue transition-colors">
              {machine ? 'Save Changes' : 'Add Machine'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddMachineModal;
