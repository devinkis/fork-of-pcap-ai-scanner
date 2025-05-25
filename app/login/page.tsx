// app/login/page.tsx
"use client";

import React, { useState, FormEvent, useEffect, Suspense } from 'react'; // Tambahkan Suspense
import { useRouter, useSearchParams } from 'next/navigation';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertCircle, LogInIcon, Loader2 } from "lucide-react"; // Tambahkan Loader2 untuk fallback
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import Link from 'next/link';

// Komponen LoginButton bisa tetap sama
function LoginButton({ pending }: { pending: boolean }) {
  return (
    <Button className="w-full h-11 text-base font-semibold" type="submit" aria-disabled={pending} disabled={pending}>
      {pending ? (
        <>
          <LogInIcon className="mr-2 h-5 w-5 animate-spin" />
          Logging in...
        </>
      ) : (
        <>
          <LogInIcon className="mr-2 h-5 w-5" />
          Login
        </>
      )}
    </Button>
  );
}

// Buat komponen baru untuk konten yang menggunakan useSearchParams
function LoginFormContent() {
  const router = useRouter();
  const searchParams = useSearchParams(); // useSearchParams digunakan di sini
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | undefined>(undefined);
  const [callbackUrl, setCallbackUrl] = useState("/");

  useEffect(() => {
    const cbUrl = searchParams?.get("callbackUrl");
    if (cbUrl) {
      setCallbackUrl(decodeURIComponent(cbUrl));
    }
    const errorParam = searchParams?.get("error");
    if (errorParam === "session_expired") {
      setErrorMessage("Your session has expired. Please log in again.");
    } else if (errorParam === "server_config_error") {
      setErrorMessage("Server configuration error. Please contact support.");
    }
  }, [searchParams]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setErrorMessage(undefined);

    if (!email.trim() || !password.trim()) {
      setErrorMessage("Email and password are required.");
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email.trim(), password: password }),
        credentials: "include",
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        setErrorMessage(result.error || 'Login failed. Please try again.');
      } else {
        console.log("Login successful, redirecting to:", callbackUrl);
        window.location.href = callbackUrl;
      }
    } catch (error) {
      console.error('Login submission error:', error);
      setErrorMessage('An unexpected error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
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
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={isLoading}
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
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLoading}
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
  );
}


export default function LoginPage() {
  // Fallback UI sederhana
  const fallbackUI = (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-10rem)]">
      <Loader2 className="h-12 w-12 animate-spin text-blue-600" />
      <p className="mt-4 text-muted-foreground">Loading login page...</p>
    </div>
  );

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-4 bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-900 dark:to-slate-800">
      <div className="w-full max-w-md">
        <Suspense fallback={fallbackUI}>
          <LoginFormContent />
        </Suspense>
        <p className="mt-8 text-center text-xs text-gray-500 dark:text-gray-400">
          &copy; {new Date().getFullYear()} PCAP AI Scanner. All rights reserved.
        </p>
      </div>
    </main>
  );
}
