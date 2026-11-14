import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VitalsShield Operator",
  description: "Operator dashboard for the VitalsShield PKI and telemetry spine",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
