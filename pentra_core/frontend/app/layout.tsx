import type { Metadata, Viewport } from 'next'
import { Space_Grotesk, JetBrains_Mono, Inter } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import './globals.css'

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-heading',
  display: 'swap',
  weight: ['300', '400', '500', '600', '700'],
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
  weight: ['300', '400', '500', '600', '700'],
})

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-body',
  display: 'swap',
  weight: ['300', '400', '500', '600', '700'],
})

export const metadata: Metadata = {
  title: 'PENTRA_CMD // SYSTEM_COMMAND_CENTER',
  description: 'AI-powered penetration testing and tactical command platform',
  icons: { icon: '/favicon.ico' },
}

export const viewport: Viewport = {
  themeColor: '#0e0e0e',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const showAnalytics = process.env.VERCEL === '1'

  return (
    <html lang="en" className={`dark ${spaceGrotesk.variable} ${jetbrainsMono.variable} ${inter.variable}`}>
      <body className="font-sans antialiased bg-background text-foreground overflow-x-hidden selection:bg-primary-container selection:text-white">
        {children}
        {showAnalytics ? <Analytics /> : null}
      </body>
    </html>
  )
}
