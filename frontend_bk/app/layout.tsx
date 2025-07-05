
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "OIDC Demo",
  description: "OIDC Demo with Go and Next.js",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="container mx-auto p-4">
          <h1 className="text-2xl font-bold mb-4">OIDC Demo</h1>
          {children}
        </div>
      </body>
    </html>
  );
}
