import type { Metadata } from "next";
import "./globals.css";
import "./tokens.css";

export const metadata: Metadata = {
  title: "RuyaShield",
  description: "Authorized-scope security assessment for the assets you own or are permitted to test.",
};

// The app shell lives in (app)/layout.tsx and the public site chrome in (site)/layout.tsx; URLs are unchanged.
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
