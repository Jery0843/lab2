export default function SimilarMachinesSkeleton() {
  return (
    <div className="text-center py-6 md:py-8">
      <div className="animate-pulse">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="bg-terminal-bg border border-cyber-green/30 rounded-lg p-3 md:p-4">
              <div className="h-5 md:h-6 bg-gray-700/50 rounded mb-3 w-3/4"></div>
              <div className="h-3 md:h-4 bg-gray-700/50 rounded mb-2 w-full"></div>
              <div className="h-3 md:h-4 bg-gray-700/50 rounded w-1/2"></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}