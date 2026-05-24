import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { QueryProvider } from "@/components/providers/QueryProvider";
import { AuthProvider } from "@/components/providers/AuthProvider";
import { TelemetryProvider } from "@/components/providers/TelemetryProvider";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "SENTINEL APEX | AI-Native Cyber Intelligence Platform",
  description: "CYBERDUDEBIVASH® SENTINEL APEX — World's most advanced AI-native cyber intelligence infrastructure",
  keywords: ["threat intelligence", "AI SOC", "cybersecurity", "CTI", "MSSP"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-gray-950 text-gray-100 antialiased`}>
        <TelemetryProvider>
          <AuthProvider>
            <QueryProvider>
              {children}
            </QueryProvider>
          </AuthProvider>
        </TelemetryProvider>
      </body>
    </html>
  );
}
