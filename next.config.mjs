// next.config.js

/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: (config, { isServer }) => {
    // Untuk mencegah error UnhandledSchemeError saat ada import "node:*"
    config.resolve.alias = {
      ...config.resolve.alias,
      'node:console': 'console',
      'node:crypto': 'crypto',
      'node:diagnostics_channel': false, // disable jika tidak perlu
    };

    // Opsional: fallback jika diperlukan untuk modul-modul Node
    config.resolve.fallback = {
      ...config.resolve.fallback,
      console: false,
      crypto: false,
      diagnostics_channel: false,
    };

    return config;
  },
};

module.exports = nextConfig;
