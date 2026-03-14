"use client"

export function GradientMesh() {
  return (
    <div className="absolute inset-0 overflow-hidden">
      {/* Base gradient */}
      <div className="absolute inset-0 bg-base" />
      
      {/* Animated gradient blobs */}
      <div 
        className="absolute w-[600px] h-[600px] rounded-full opacity-[0.05] blur-3xl animate-gradient-mesh"
        style={{
          background: "radial-gradient(circle, #3b82f6 0%, transparent 70%)",
          top: "10%",
          left: "20%",
        }}
      />
      <div 
        className="absolute w-[500px] h-[500px] rounded-full opacity-[0.04] blur-3xl animate-gradient-mesh"
        style={{
          background: "radial-gradient(circle, #8b5cf6 0%, transparent 70%)",
          bottom: "10%",
          right: "10%",
          animationDelay: "-5s",
        }}
      />
      <div 
        className="absolute w-[400px] h-[400px] rounded-full opacity-[0.03] blur-3xl animate-gradient-mesh"
        style={{
          background: "radial-gradient(circle, #3b82f6 0%, transparent 70%)",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          animationDelay: "-10s",
        }}
      />
    </div>
  )
}
