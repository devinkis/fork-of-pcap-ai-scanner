// app/login/page.tsx
import { Suspense } from "react";
import { LoginForm } from "@/components/login-form"; //
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"; //
import { Skeleton } from "@/components/ui/skeleton"; //
import { Shield } from "lucide-react";

export default function LoginPage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-slate-100 to-slate-300 dark:from-slate-900 dark:to-slate-800 p-4">
      <div className="mb-8 text-center">
        <Link href="/" className="inline-flex items-center gap-2 text-2xl font-bold text-slate-800 dark:text-slate-200">
          <Shield className="h-8 w-8 text-primary" />
          <span>PCAP Scanner</span>
        </Link>
      </div>
      <Card className="w-full max-w-md shadow-2xl rounded-xl">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-semibold">Welcome Back!</CardTitle>
          <CardDescription>Enter your credentials to access your network insights.</CardDescription>
        </CardHeader>
        <CardContent className="p-6">
          <Suspense fallback={<LoginFormSkeleton />}>
            <LoginForm />
          </Suspense>
        </CardContent>
      </Card>
      <p className="mt-8 text-center text-xs text-muted-foreground">
        © {new Date().getFullYear()} PCAP Scanner Inc. All rights reserved.
      </p>
    </div>
  );
}

function LoginFormSkeleton() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-4 w-16 rounded" />
        <Skeleton className="h-10 w-full rounded-md" />
      </div>
      <div className="space-y-2">
        <Skeleton className="h-4 w-16 rounded" />
        <Skeleton className="h-10 w-full rounded-md" />
      </div>
      <Skeleton className="h-10 w-full rounded-md mt-2" />
    </div>
  );
}
