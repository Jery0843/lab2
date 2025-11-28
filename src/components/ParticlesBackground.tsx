"use client";

import { useEffect, useRef } from "react";

interface ParticlesBackgroundProps {
  particleCount?: number;
  particleColor?: string; // overrides theme color
  linkColor?: string; // overrides theme color
  maxLinkDistance?: number; // in px
  speed?: number; // pixels per frame baseline
  opacity?: number; // particle opacity
  themeAware?: boolean; // use CSS variables for colors
}

// Theme-aware 3D-inspired neon particles with depth, glow, and links (no blue hues)
export default function ParticlesBackground({
  particleCount = 100,
  particleColor,
  linkColor,
  maxLinkDistance = 140,
  speed = 0.4,
  opacity = 0.7,
  themeAware = true,
}: ParticlesBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const paletteRef = useRef<{ particle: string; link: string; particleHex: string; linkHex: string } | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = Math.max(1, window.devicePixelRatio || 1);

    const computePalette = () => {
      if (!themeAware) {
        const pHex = particleColor || "#00ff41";
        const lHex = linkColor || "#ff0080";
        const p = hexToRGBA(pHex, opacity);
        const l = hexToRGBA(lHex, 0.18);
        paletteRef.current = { particle: p, link: l, particleHex: pHex, linkHex: lHex };
        return;
      }
      const root = document.documentElement;
      const styles = getComputedStyle(root);
      // Pull from CSS variables; avoid blue hues per request
      const green = styles.getPropertyValue("--cyber-green").trim() || "#00ff41";
      const pink = styles.getPropertyValue("--cyber-pink").trim() || "#ff0080";
      const particleHex = particleColor || green;
      const linkHex = linkColor || pink;
      paletteRef.current = {
        particle: hexToRGBA(particleHex, opacity),
        link: hexToRGBA(linkHex, 0.18),
        particleHex,
        linkHex,
      };
    };

    computePalette();

    // Observe theme class changes on <html>
    const mo = new MutationObserver(() => computePalette());
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

    const resize = () => {
      const { innerWidth, innerHeight } = window;
      canvas.width = Math.floor(innerWidth * dpr);
      canvas.height = Math.floor(innerHeight * dpr);
      canvas.style.width = `${innerWidth}px`;
      canvas.style.height = `${innerHeight}px`;
    };

    resize();
    window.addEventListener("resize", resize);

    type Particle = {
      x: number;
      y: number;
      z: number; // depth 0..1 (near..far)
      vx: number;
      vy: number;
      r: number;
      hue: 'green' | 'pink';
      swirl: number; // angular velocity factor
    };

    const rand = (min: number, max: number) => Math.random() * (max - min) + min;

    const count = Math.floor(particleCount * (Math.min(window.innerWidth, 1600) / 1600));
    const particles: Particle[] = Array.from({ length: count }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      z: Math.random(),
      vx: (Math.random() - 0.5) * speed * dpr,
      vy: (Math.random() - 0.5) * speed * dpr,
      r: rand(1.2, 2.2) * dpr,
      hue: Math.random() < 0.65 ? 'green' : 'pink',
      swirl: rand(-0.0006, 0.0006),
    }));

    const bgGradient = () => {
      const g = ctx.createRadialGradient(
        canvas.width * 0.5,
        canvas.height * 0.4,
        0,
        canvas.width * 0.5,
        canvas.height * 0.6,
        Math.max(canvas.width, canvas.height) * 0.7
      );
      const isLight = document.documentElement.classList.contains('light');
      if (isLight) {
        // Light mode: soft paper glow
        g.addColorStop(0, "rgba(255, 255, 255, 0.8)");
        g.addColorStop(1, "rgba(241, 245, 249, 0.9)");
      } else {
        // Dark mode: green-tinted vignette
        g.addColorStop(0, "rgba(0, 255, 65, 0.05)");
        g.addColorStop(1, "rgba(0, 0, 0, 0.65)");
      }
      return g;
    };

    const particleColorRGBA = () => (paletteRef.current ? paletteRef.current.particle : hexToRGBA("#00ff41", opacity));
    const linkColorRGBA = () => (paletteRef.current ? paletteRef.current.link : hexToRGBA("#ff0080", 0.18));

    // Mouse influence (subtle, enhances depth without overdraw)
    const mouse = { x: canvas.width / 2, y: canvas.height / 3 };
    const onMouseMove = (e: MouseEvent) => {
      mouse.x = e.clientX * dpr;
      mouse.y = e.clientY * dpr;
    };
    window.addEventListener("mousemove", onMouseMove);

    const step = () => {
      // subtle background gradient
      ctx.fillStyle = bgGradient();
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // update and draw particles (with depth, glow, and subtle swirl)
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        // swirl about center scaled by depth
        const cx = canvas.width * 0.5;
        const cy = canvas.height * 0.5;
        const dx = p.x - cx;
        const dy = p.y - cy;
        const angle = p.swirl * (1.5 - p.z);
        const cosA = Math.cos(angle);
        const sinA = Math.sin(angle);
        const rx = dx * cosA - dy * sinA;
        const ry = dx * sinA + dy * cosA;
        p.x = cx + rx + p.vx * (1.2 - p.z * 0.8) * 1.5;
        p.y = cy + ry + p.vy * (1.2 - p.z * 0.8) * 1.5;

        // bounce on edges
        if (p.x <= 0 || p.x >= canvas.width) p.vx *= -1;
        if (p.y <= 0 || p.y >= canvas.height) p.vy *= -1;

        // slight mouse parallax pull
        const mx = (mouse.x - p.x) * 0.00003;
        const my = (mouse.y - p.y) * 0.00003;
        p.x += mx * dpr * 2;
        p.y += my * dpr * 2;

        // depth scaling and glow
        const depthScale = 0.6 + p.z * 0.9;
        const radius = p.r * (1.2 + (1 - p.z) * 1.2);
        const pHex = paletteRef.current?.particleHex || '#00ff41';
        const lHex = paletteRef.current?.linkHex || '#ff0080';
        const colorHex = p.hue === 'green' ? pHex : lHex;
        const alphaBoost = 0.5 + (1 - p.z) * 0.5;

        const grad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, radius * 3);
        grad.addColorStop(0, hexToRGBA(colorHex, 0.65 * alphaBoost));
        grad.addColorStop(0.5, hexToRGBA(colorHex, 0.25 * alphaBoost));
        grad.addColorStop(1, hexToRGBA(colorHex, 0));

        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius * depthScale, 0, Math.PI * 2);
        ctx.fill();
      }

      // draw links for mid/near particles to enhance 3D layering
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i];
          const b = particles[j];
          const md = (a.z + b.z) * 0.5;
          if (md < 0.25) continue; // skip very far
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.hypot(dx, dy);
          if (dist < maxLinkDistance * dpr) {
            const alpha = (1 - dist / (maxLinkDistance * dpr)) * (0.35 + (1 - md) * 0.35);
            const lc = paletteRef.current?.linkHex || '#ff0080';
            ctx.strokeStyle = hexToRGBA(lc, Math.max(0, Math.min(1, alpha)));
            ctx.lineWidth = (0.4 + (1 - md) * 0.6) * dpr;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      rafRef.current = requestAnimationFrame(step);
    };

    rafRef.current = requestAnimationFrame(step);

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMouseMove);
      mo.disconnect();
    };
  }, [particleCount, particleColor, linkColor, maxLinkDistance, speed, opacity, themeAware]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      style={{ position: "fixed", inset: 0, zIndex: -1, pointerEvents: "none" }}
    />
  );
}

function hexToRGBA(hex: string, a = 1) {
  const c = hex.replace("#", "");
  const bigint = parseInt(c.length === 3 ? c.split("").map((ch) => ch + ch).join("") : c, 16);
  const r = (bigint >> 16) & 255;
  const g = (bigint >> 8) & 255;
  const b = bigint & 255;
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

function setAlpha(rgba: string, a: number) {
  return rgba.replace(/rgba\(([^)]+)\)/, (_m, inner) => {
    const parts = inner.split(",").map((p: string) => p.trim());
    return `rgba(${parts[0]}, ${parts[1]}, ${parts[2]}, ${Math.max(0, Math.min(1, a))})`;
  });
}
