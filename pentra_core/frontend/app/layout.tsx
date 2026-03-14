import type { Metadata, Viewport } from 'next'
import { Analytics } from '@vercel/analytics/next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Pentra - Autonomous Offensive Security',
  description: 'AI-driven penetration testing platform',
}

export const viewport: Viewport = {
  themeColor: '#09090b',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const showAnalytics = process.env.VERCEL === '1'

  return (
    <html lang="en" className="dark">
      <body className="font-sans antialiased">
        {children}
        {showAnalytics ? <Analytics /> : null}
      </body>
    </html>
  )
}
