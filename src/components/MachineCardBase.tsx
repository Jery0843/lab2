'use client';

import { FaDesktop, FaWindows, FaLinux, FaEdit, FaTrash, FaEye, FaClock, FaExternalLinkAlt } from 'react-icons/fa';

interface BaseMachine {
  id: string;
  name?: string;
  title?: string;
  os?: string;
  difficulty: string;
  status: string;
  dateCompleted: string | null;
  tags: string[] | string;
  writeup: string | null;
  url?: string;
  roomCode?: string;
  points?: number;
}

interface MachineCardBaseProps {
  machine: BaseMachine;
  provider: 'htb' | 'thm';
  isAdminMode: boolean;
  onViewWriteup: (machine: BaseMachine) => void;
  onEdit: (machine: BaseMachine) => void;
  onDelete: (machineId: string) => void;
}

const MachineCardBase = ({ machine, provider, isAdminMode, onViewWriteup, onEdit, onDelete }: MachineCardBaseProps) => {
  const getOSIcon = () => {
    if (!machine.os) return <FaDesktop className="text-cyber-purple" />;
    
    switch (machine.os.toLowerCase()) {
      case 'windows':
        return <FaWindows className="text-cyber-blue" />;
      case 'linux':
        return <FaLinux className="text-cyber-green" />;
      default:
        return <FaDesktop className="text-cyber-purple" />;
    }
  };

  const getDifficultyColor = () => {
    switch (machine.difficulty.toLowerCase()) {
      case 'easy':
        return 'text-green-400 border-green-400';
      case 'medium':
        return 'text-yellow-400 border-yellow-400';
      case 'hard':
        return 'text-red-400 border-red-400';
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

  const getProviderColor = () => {
    return provider === 'htb' ? 'text-cyber-green' : 'text-cyber-purple';
  };

  const getProviderAccent = () => {
    return provider === 'htb' ? 'border-cyber-green' : 'border-cyber-purple';
  };

  const getProviderHover = () => {
    return provider === 'htb' ? 'hover:border-cyber-green' : 'hover:border-cyber-purple';
  };

  const machineName = machine.name || machine.title || 'Unknown';
  const detailPath = `/machines/${provider}/${machine.id}`;

  return (
    <div className={`rounded-lg backdrop-blur-sm bg-black/10 light:bg-white/20 border border-white/5 p-6 transition-all duration-300 group`}>
      {/* Header */}
      <div className="flex justify-between items-start mb-4">
        <div className="flex items-center space-x-3">
          {machine.os && getOSIcon()}
          <h3 className={`text-xl font-bold ${getProviderColor()} group-hover:text-cyber-blue transition-colors`}>
            {machineName}
          </h3>
        </div>
        <div className={`px-2 py-1 border rounded text-xs font-bold ${getDifficultyColor()}`}>
          {machine.difficulty}
        </div>
      </div>

      {/* Provider Badge */}
      <div className={`inline-flex items-center space-x-2 px-2 py-1 border rounded-full text-xs font-semibold mb-3 ${getProviderColor()} ${getProviderAccent()}/30`}>
        <span>{provider === 'htb' ? 'HTB' : 'THM'}</span>
        {provider === 'htb' && machine.points && <span>• {machine.points} pts</span>}
      </div>

      {/* Status Badge */}
      <div className={`inline-flex items-center space-x-2 px-3 py-1 border rounded-full text-sm font-semibold mb-4 ${getStatusColor()}`}>
        {machine.status === 'In Progress' && <FaClock className="w-3 h-3" />}
        <span>{machine.status}</span>
      </div>

      {/* Date */}
      {machine.dateCompleted && (
        <p className="text-sm text-gray-400 mb-4">
          <strong>Completed:</strong> {new Date(machine.dateCompleted).toLocaleDateString()}
        </p>
      )}

      {/* Tags */}
      <div className="flex flex-wrap gap-2 mb-4">
        {(() => {
          const tags = Array.isArray(machine.tags) 
            ? machine.tags 
            : typeof machine.tags === 'string' 
              ? (machine.tags as string).split(',').map(tag => tag.trim())
              : [];
          
          return tags.map((tag: string, index: number) => (
            <span
              key={index}
              className={`px-2 py-1 ${getProviderColor()}/10 ${getProviderColor()} text-xs rounded border ${getProviderAccent()}/30`}
            >
              {tag}
            </span>
          ));
        })()}
      </div>

      {/* Actions */}
      <div className="flex justify-between items-center">
        <div className="flex space-x-2">
          <a
            href={detailPath}
            className={`flex items-center space-x-2 px-4 py-2 rounded font-semibold transition-all duration-300 border-2 shadow-md ${provider === 'htb' ? 'bg-cyber-green border-cyber-green' : 'bg-cyber-purple border-cyber-purple'} text-white hover:bg-cyber-blue hover:text-white hover:shadow-xl hover:border-cyber-blue transform hover:scale-105`}
          >
            <FaEye className="text-white" />
            <span className="text-white">View Details</span>
          </a>

          {/* External Link for THM */}
          {provider === 'thm' && machine.url && (
            <a
              href={machine.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-2 px-3 py-2 rounded font-semibold transition-all duration-300 border border-cyber-purple/50 text-cyber-purple hover:bg-cyber-purple hover:text-white"
              title="Open on TryHackMe"
            >
              <FaExternalLinkAlt />
            </a>
          )}
        </div>

        {isAdminMode && (
          <div className="flex space-x-2">
            <button
              onClick={() => onEdit(machine)}
              className="p-2 text-cyber-blue hover:text-cyber-green transition-colors"
              title={`Edit ${provider === 'htb' ? 'Machine' : 'Room'}`}
            >
              <FaEdit />
            </button>
            <button
              onClick={() => onDelete(machine.id)}
              className="p-2 text-red-400 hover:text-red-300 transition-colors"
              title={`Delete ${provider === 'htb' ? 'Machine' : 'Room'}`}
            >
              <FaTrash />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default MachineCardBase;
