/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack(config, { isServer }) {
    if (isServer) {
      config.resolve.alias = {
        ...config.resolve.alias,
        'node:crypto': 'crypto',
        'node:console': 'console',
        'node:fs': 'fs',
        'node:path': 'path',
        'node:util': 'util',
        'node:stream': 'stream',
        'node:http': 'http',
        'node:https': 'https',
      };
    }

    return config;
  },
};

export default nextConfig;
