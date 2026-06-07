import React from "react";

export function Logo({ size = 32, className = "" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 128 128"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`adaptive-logo ${className}`}
      style={{ filter: "drop-shadow(0 0 8px var(--accent))" }}
    >
      {/* Outer shield structure */}
      <path
        d="M64 8C88 18 104 22 112 28C114 36 116 54 112 80C106 102 82 116 64 120C46 116 22 102 16 80C12 54 14 36 16 28C24 22 40 18 64 8Z"
        stroke="url(#shieldGrad)"
        strokeWidth="6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Internal scanning grid / radar arcs */}
      <path
        d="M64 24C41.9086 24 24 41.9086 24 64C24 73.6 28.2 82.2 34.9 88.2"
        stroke="var(--accent-2)"
        strokeWidth="4"
        strokeLinecap="round"
        opacity="0.6"
      />
      
      <path
        d="M64 36C48.536 36 36 48.536 36 64C36 70.8 38.4 77 42.4 81.8"
        stroke="var(--accent)"
        strokeWidth="4"
        strokeLinecap="round"
        opacity="0.8"
      />

      {/* Center target lock */}
      <circle
        cx="64"
        cy="64"
        r="14"
        fill="url(#coreGrad)"
        stroke="var(--accent)"
        strokeWidth="3.5"
      />

      {/* Crosshairs / Target signal */}
      <line x1="64" y1="42" x2="64" y2="50" stroke="var(--accent)" strokeWidth="4" strokeLinecap="round" />
      <line x1="64" y1="78" x2="64" y2="86" stroke="var(--accent)" strokeWidth="4" strokeLinecap="round" />
      <line x1="42" y1="64" x2="50" y2="64" stroke="var(--accent)" strokeWidth="4" strokeLinecap="round" />
      <line x1="78" y1="64" x2="86" y2="64" stroke="var(--accent)" strokeWidth="4" strokeLinecap="round" />

      {/* Radar sweep beam line */}
      <line
        x1="64"
        y1="64"
        x2="92"
        y2="36"
        stroke="var(--accent)"
        strokeWidth="3"
        strokeLinecap="round"
        style={{
          transformOrigin: "64px 64px",
          animation: "radarSweep 5s linear infinite"
        }}
      />

      {/* Definitions for Gradients */}
      <defs>
        <linearGradient id="shieldGrad" x1="16" y1="8" x2="112" y2="120" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--accent)" />
          <stop offset="0.5" stopColor="var(--accent-2)" />
          <stop offset="1" stopColor="var(--accent)" />
        </linearGradient>
        <radialGradient id="coreGrad" cx="64" cy="64" r="14" gradientUnits="userSpaceOnUse">
          <stop stopColor="var(--accent)" stopOpacity="0.4" />
          <stop offset="1" stopColor="var(--accent)" stopOpacity="0.1" />
        </radialGradient>
      </defs>
    </svg>
  );
}
