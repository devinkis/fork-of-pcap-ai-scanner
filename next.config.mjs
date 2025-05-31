// next.config.mjs
/** @type {import('next').NextConfig} */
const nextConfig = {
  // ... konfigurasi Anda yang lain ...
  webpack: (config, { isServer, webpack }) => {
    // Penting: Hanya terapkan untuk build server-side jika memungkinkan
    // atau jika Anda yakin polyfill tidak akan membebani klien.
    // Namun, error ini biasanya terjadi saat bundling kode yang seharusnya server-side.

    // Polyfill untuk modul node bawaan (hati-hati, ini bisa menambah ukuran bundle)
    // Untuk `node:` prefix, webpack 5 seharusnya sudah bisa resolve by default untuk node targets.
    // Masalahnya mungkin pada target environment (edge/client).

    // Jika target bukan server Node.js penuh, kita bisa coba fallback ke false
    // atau alias ke polyfill browser jika ada.
    if (!isServer) {
      // Untuk client-side, banyak modul 'node:' tidak akan berfungsi.
      // Jika @elastic/elasticsearch masuk ke bundle klien, itu masalah besar.
      // Kode logger SIEM tidak boleh ada di bundle klien.
      config.resolve.fallback = {
        ...config.resolve.fallback,
        "console": false, // atau require.resolve("console-browserify")
        "crypto": false, // atau require.resolve("crypto-browserify")
        "dns": false,
        "https": false, // atau require.resolve("https-browserify")
        "http": false, // atau require.resolve("stream-http")
        "net": false,
        "tls": false,
        "fs": false,
        "path": false, // atau require.resolve("path-browserify")
        "stream": false, // atau require.resolve("stream-browserify")
        "zlib": false, // atau require.resolve("browserify-zlib")
        "diagnostics_channel": false,
        // Tambahkan modul 'node:' lain yang bermasalah
      };
    }

    // Untuk Next.js 12+, Anda mungkin tidak perlu ini jika targetnya adalah Node.js.
    // Konfigurasi ini lebih relevan jika Webpack salah menginterpretasikan target.
    // config.resolve.alias = {
    //   ...config.resolve.alias,
    //   'node:console': 'console',
    //   'node:crypto': 'crypto',
    //   // ... dan seterusnya untuk modul lain yang bermasalah
    // };

    // Plugin untuk menyediakan variabel global Node.js jika diperlukan (biasanya untuk library lama)
    // config.plugins.push(
    //   new webpack.ProvidePlugin({
    //     process: 'process/browser',
    //     Buffer: ['buffer', 'Buffer'],
    //   })
    // );

    return config;
  },
};

export default nextConfig;
