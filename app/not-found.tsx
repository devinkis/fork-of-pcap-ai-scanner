// app/not-found.tsx
import Link from 'next/link'
import { Button } from "@/components/ui/button"
import { AlertTriangle, Home } from 'lucide-react'
import { Skeleton } from "@/components/ui/skeleton"; // Pastikan impor ini ada dan benar

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-10rem)] bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-900 dark:to-slate-800 text-slate-800 dark:text-white p-4 text-center">
      <AlertTriangle className="w-20 h-20 sm:w-24 sm:h-24 text-yellow-500 dark:text-yellow-400 mb-6 sm:mb-8 animate-bounce" />
      <h1 className="text-5xl sm:text-6xl font-bold mb-3 sm:mb-4">404</h1>
      <h2 className="text-2xl sm:text-3xl font-semibold mb-4 sm:mb-6 text-slate-700 dark:text-slate-300">Page Not Found</h2>
      <p className="text-base sm:text-lg text-slate-600 dark:text-slate-400 mb-6 sm:mb-8 max-w-md">
        Oops! The page you're looking for doesn't seem to exist. It might have been moved, deleted, or maybe you just mistyped the URL.
      </p>
      
      {/* Baris berikut adalah contoh jika Anda ingin menggunakan Skeleton di sini.
          Jika Anda tidak menggunakannya, Anda bisa menghapus bagian ini.
          Namun, impor Skeleton tetap diperlukan jika ada komponen lain (misalnya layout)
          yang mungkin merender halaman not-found ini dan menggunakan Skeleton.
      */}
      {/* <div className="space-y-2 w-full max-w-sm mb-8">
        <p className="text-sm text-slate-500 dark:text-slate-400">Loading placeholder:</p>
        <Skeleton className="h-8 w-full bg-slate-300 dark:bg-slate-700" />
        <Skeleton className="h-8 w-3/4 bg-slate-300 dark:bg-slate-700" />
      </div> 
      */}

      <Link href="/">
        <Button variant="secondary" size="lg" className="text-slate-900 bg-yellow-400 hover:bg-yellow-500 dark:bg-yellow-500 dark:hover:bg-yellow-600 transition-colors text-base sm:text-lg px-6 py-3">
          <Home className="mr-2 h-5 w-5" />
          Go Back Home
        </Button>
      </Link>
      <p className="mt-10 sm:mt-12 text-xs sm:text-sm text-slate-500 dark:text-slate-500">
        If you believe this is an error, please double-check the URL or contact support.
      </p>
    </div>
  )
}
