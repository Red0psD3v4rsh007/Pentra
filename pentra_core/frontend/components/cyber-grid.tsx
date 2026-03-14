"use client"

export function CyberGrid() {
  return (
    <div className="absolute inset-0 overflow-hidden">
      {/* Deep black base */}
      <div className="absolute inset-0 bg-[#030305]" />
      
      {/* Subtle grid pattern */}
      <div 
        className="absolute inset-0 animate-grid-pulse"
        style={{
          backgroundImage: `
            linear-gradient(rgba(59, 130, 246, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(59, 130, 246, 0.03) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
        }}
      />
      
      {/* Radial gradient overlay for depth */}
      <div 
        className="absolute inset-0"
        style={{
          background: 'radial-gradient(ellipse at 50% 50%, transparent 0%, #030305 70%)',
        }}
      />
      
      {/* Primary glow orb - top center */}
      <div 
        className="absolute w-[600px] h-[600px] rounded-full animate-glow-pulse"
        style={{
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.15) 0%, transparent 70%)',
          top: '-10%',
          left: '50%',
          transform: 'translateX(-50%)',
        }}
      />
      
      {/* Secondary glow orb - bottom left */}
      <div 
        className="absolute w-[400px] h-[400px] rounded-full animate-glow-pulse"
        style={{
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.08) 0%, transparent 70%)',
          bottom: '10%',
          left: '10%',
          animationDelay: '-3s',
        }}
      />
      
      {/* Accent glow - right side */}
      <div 
        className="absolute w-[300px] h-[500px] rounded-full animate-glow-pulse"
        style={{
          background: 'radial-gradient(ellipse, rgba(34, 197, 94, 0.05) 0%, transparent 70%)',
          top: '30%',
          right: '5%',
          animationDelay: '-5s',
        }}
      />
      
      {/* Scan line effect */}
      <div 
        className="absolute left-0 right-0 h-[2px] animate-scan-line pointer-events-none"
        style={{
          background: 'linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.3), transparent)',
          boxShadow: '0 0 20px 5px rgba(59, 130, 246, 0.1)',
        }}
      />
      
      {/* Noise texture overlay */}
      <div 
        className="absolute inset-0 opacity-[0.015] pointer-events-none"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
        }}
      />
      
      {/* Vignette effect */}
      <div 
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.4) 100%)',
        }}
      />
    </div>
  )
}
