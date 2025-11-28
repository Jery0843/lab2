'use client';

import { FaDesktop, FaWindows, FaLinux, FaEdit, FaTrash, FaEye, FaClock } from 'react-icons/fa';

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

interface MachineCardProps {
  machine: Machine;
  isAdminMode: boolean;
  basePath?: string; // Optional base path for navigation
  onViewWriteup: (machine: Machine) => void;
  onEdit: (machine: Machine) => void;
  onDelete: (machineId: string) => void;
}

const MachineCard = ({ machine, isAdminMode, basePath = '/machines', onViewWriteup, onEdit, onDelete }: MachineCardProps) => {
  const getOSIcon = () => {
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

  return (
    <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 transition-all duration-300 group">
      {/* Header */}
      <div className="flex justify-between items-start mb-4">
        <div className="flex items-center space-x-3">
          {getOSIcon()}
          <h3 className="text-xl font-bold text-cyber-green group-hover:text-cyber-blue transition-colors">
            {machine.name}
          </h3>
        </div>
        <div className={`px-2 py-1 border rounded text-xs font-bold ${getDifficultyColor()}`}>
          {machine.difficulty}
        </div>
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
        {machine.tags.map((tag, index) => (
          <span
            key={index}
            className="px-2 py-1 bg-cyber-green/10 text-cyber-green text-xs rounded border border-cyber-green/30"
          >
            {tag}
          </span>
        ))}
      </div>

      {/* Actions */}
      <div className="flex justify-between items-center">
        <a
          href={`${basePath}/${machine.id}`}
          className="flex items-center space-x-2 px-4 py-2 rounded font-semibold transition-all duration-300 border-2 shadow-md bg-cyber-green hover:bg-cyber-blue hover:shadow-xl border-cyber-green hover:border-cyber-blue transform hover:scale-105 text-white hover:text-white"
        >
          <FaEye className="text-white" />
          <span className="text-white">View Details</span>
        </a>

        {isAdminMode && (
          <div className="flex space-x-2">
            <button
              onClick={() => onEdit(machine)}
              className="p-2 text-cyber-blue hover:text-cyber-green transition-colors"
              title="Edit Machine"
            >
              <FaEdit />
            </button>
            <button
              onClick={() => onDelete(machine.id)}
              className="p-2 text-red-400 hover:text-red-300 transition-colors"
              title="Delete Machine"
            >
              <FaTrash />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default MachineCard;
