// next.config.mjs
/** @type {import('next').NextConfig} */
const nextConfig = {
  // ...
  webpack: (config, { isServer, nextRuntime }) => {
    if (isServer && nextRuntime === 'nodejs') {
      config.externals = [
        ...(config.externals || []),
        (context, request, callback) => {
          // Daftar modul yang akan dieksternalisasi
          const externalsList = [
            'undici',
            '@elastic/elasticsearch',
            '@elastic/transport',
            // Anda bisa menambahkan modul 'node:...' di sini jika masih bermasalah,
            // meskipun seharusnya tidak perlu jika targetnya Node.js.
            // Contoh: /^node:/
          ];

          if (externalsList.some(mod => request.startsWith(mod) || (mod instanceof RegExp && mod.test(request)))) {
            return callback(null, `commonjs ${request}`);
          }
          callback();
        },
      ];
    }

    if (!isServer || nextRuntime === 'edge') {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        "console": false, "crypto": false, "dns": false, "http": false,
        "https": false, "net": false, "tls": false, "fs": false,
        "path": false, "stream": false, "zlib": false,
        "diagnostics_channel": false, "os": false, "tty": false, "util": false,
      };
    }
    return config;
  },
};
export default nextConfig;
