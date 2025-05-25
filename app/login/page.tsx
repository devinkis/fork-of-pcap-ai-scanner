// app/login/page.tsx
"use client";

import { useState, FormEvent } from 'react'; // Ditambahkan FormEvent dan useState
import { useRouter } from 'next/navigation'; // Ditambahkan useRouter untuk redirect
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
// HAPUS: useFormState dan useFormStatus tidak lagi digunakan jika tidak ada Server Action
// HAPUS: import { authenticateCustomUser } from './actions'; 
import { AlertCircle, LogInIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import Link from 'next/link';

// Komponen LoginButton bisa disederhanakan atau state loading dikelola di LoginPage
function LoginButton({ pending }: { pending: boolean }) {
  return (
    <Button className="w-full" type="submit" aria-disabled={pending} disabled={pending}>
      {pending ? (
        <>
          <LogInIcon className="mr-2 h-4 w-4 animate-spin" />
          Logging in...
        </>
      ) : (
        <>
          <LogInIcon className="mr-2 h-4 w-4" />
          Login
        </>
      )}
    </Button>
  );
}

export default function LoginPage() {
  const router = useRouter();
  const [errorMessage, setErrorMessage] = useState<string | undefined>(undefined);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setErrorMessage(undefined);

    const formData = new FormData(event.currentTarget);
    // const email = formData.get('email') as string;
    // const password = formData.get('password') as string;

    try {
      // Anda perlu mengganti ini dengan panggilan ke API route login Anda
      // Contoh:
      const response = await fetch('/api/auth/login', { // Ganti dengan path API Anda
        method: 'POST',
        body: formData, // Kirim FormData langsung jika API Anda bisa menanganinya,
                       // atau buat objek JSON: body: JSON.stringify({ email, password })
                       // dan set header 'Content-Type': 'application/json'
      });

      const result = await response.json();

      if (!response.ok) {
        setErrorMessage(result.message || 'Login failed. Please try again.');
      } else {
        // Jika login berhasil, API mungkin mengembalikan data user atau hanya status sukses.
        // Cookie httpOnly akan disetel oleh API route.
        // Redirect ke halaman utama atau dashboard.
        console.log("Login successful, redirecting...");
        router.push('/'); // Ganti dengan path redirect yang sesuai
      }
    } catch (error) {
      console.error('Login submission error:', error);
      setErrorMessage('An unexpected error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-4 bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-900 dark:to-slate-800">
      <div className="w-full max-w-md">
        {/* Ganti form action dengan onSubmit handler */}
        <form onSubmit={handleSubmit} className="space-y-6">
          <Card className="shadow-2xl">
            <CardHeader className="space-y-1 text-center">
              <div className="flex justify-center mb-4">
                <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-blue-600 dark:text-blue-400"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
              </div>
              <CardTitle className="text-3xl font-bold tracking-tight text-gray-800 dark:text-white">Welcome Back!</CardTitle>
              <CardDescription className="text-gray-600 dark:text-gray-400">
                Enter your credentials to access your PCAP analysis dashboard.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  placeholder="name@example.com"
                  required
                  className="bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700 focus:border-blue-500 dark:focus:border-blue-500 focus:ring-blue-500 dark:focus:ring-blue-500"
                />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password">Password</Label>
                </div>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  placeholder="••••••••"
                  required
                  minLength={6}
                  className="bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700 focus:border-blue-500 dark:focus:border-blue-500 focus:ring-blue-500 dark:focus:ring-blue-500"
                />
              </div>
              {errorMessage && (
                <Alert variant="destructive" className="bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-700/50 text-red-700 dark:text-red-400">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Login Failed</AlertTitle>
                  <AlertDescription>{errorMessage}</AlertDescription>
                </Alert>
              )}
            </CardContent>
            <CardFooter className="flex flex-col items-center space-y-4">
              <LoginButton pending={isLoading} />
              <div className="mt-4 text-center text-sm text-gray-600 dark:text-gray-400">
                Don&apos;t have an account?{' '}
                <Link href="/signup" className="font-medium text-blue-600 hover:underline dark:text-blue-400">
                  Sign up
                </Link>
              </div>
            </CardFooter>
          </Card>
        </form>
        <p className="mt-8 text-center text-xs text-gray-500 dark:text-gray-400">
          &copy; {new Date().getFullYear()} PCAP AI Scanner. All rights reserved.
        </p>
      </div>
    </main>
  );
}
