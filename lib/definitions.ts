// lib/definitions.ts

/**
 * Mendefinisikan struktur data untuk sebuah analisis PCAP.
 * Ini digunakan untuk menampilkan informasi analisis di halaman dashboard.
 */
export interface Analysis {
  id: string; // Ini akan menjadi analysisId dari tabel pcap_files
  file_name: string | null; // originalName dari tabel pcap_files
  status: 'COMPLETED' | 'PROCESSING' | 'PENDING' | 'ERROR' | 'UNKNOWN'; // Anda perlu cara untuk menentukan status ini
  upload_date: string; // createdAt dari tabel pcap_files, diformat sebagai string ISO atau representasi lain
  // Tambahkan properti lain yang mungkin Anda perlukan, misalnya:
  // fileSize?: number;
  // userId?: string;
}

/**
 * Mendefinisikan struktur data untuk pengguna (User).
 * Meskipun tidak secara eksplisit diminta oleh error terakhir, ini adalah definisi umum yang baik untuk ada.
 */
export interface User {
  id: string;
  email: string;
  name: string | null;
  role: "ADMIN" | "USER";
}

// Anda bisa menambahkan definisi tipe atau interface lain yang relevan untuk aplikasi Anda di sini.
