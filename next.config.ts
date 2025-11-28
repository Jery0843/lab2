import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  // Turbopack configuration (stable)
  turbopack: {
    // Handle resolve aliases for Turbopack
    resolveAlias: {
      // Add any alias configurations if needed
    },
    // Configure resolve extensions
    resolveExtensions: ['.ts', '.tsx', '.js', '.jsx', '.json'],
    // Rules for handling different file types (equivalent to webpack loaders)
    rules: {
      // Handle any specific file transformations if needed
    },
  },
  // External packages that should not be bundled (works with both Turbopack and Webpack)
  serverExternalPackages: ['sharp', 'canvas'],
  // Webpack configuration for Cloudflare Workers compatibility (fallback for production builds)
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals = config.externals || [];
      config.externals.push({
        'sharp': 'sharp',
        'canvas': 'canvas',
      });
    }
    return config;
  },
  // Redirects for backward compatibility
  async redirects() {
    return [
      {
        source: '/htb',
        destination: '/machines/htb',
        permanent: true,
      },
      {
        source: '/htb/:slug*',
        destination: '/machines/htb/:slug*',
        permanent: true,
      },
    ];
  },
};

export default nextConfig;
