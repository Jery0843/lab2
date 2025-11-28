"use client";

import { useEffect, useRef } from "react";

interface NeuralAuroraBackgroundProps {
  density?: number; // particles per 100k px^2
  speed?: number; // base speed
  trailAlpha?: number; // 0..1, how quickly trails fade
  themeAware?: boolean; // adapt to light/dark
}

// Neural Aurora: 3D-ish flow-field particles with glow, swirl, and pulses.
export default function NeuralAuroraBackground({
  density = 0.22,
  speed = 0.8,
  trailAlpha = 0.08,
  themeAware = true,
}: NeuralAuroraBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const tRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = Math.max(1, window.devicePixelRatio || 1);

    const resize = () => {
      const w = window.innerWidth;
      const h = window.innerHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
    };
    resize();
    window.addEventListener("resize", resize);

    const isLight = () => document.documentElement.classList.contains("light");

    const getPalette = () => {
      // Read CSS vars, but avoid blue; use green + pink + amber accents
      const styles = getComputedStyle(document.documentElement);
      const green = styles.getPropertyValue("--cyber-green").trim() || "#00ff41";
      const pink = styles.getPropertyValue("--cyber-pink").trim() || "#ff0080";
      const amber = "#ffb300";
      const lightMode = themeAware && isLight();
      return {
        bg1: lightMode ? "rgba(255,255,255,0.9)" : "rgba(0,0,0,0.65)",
        bg2: lightMode ? "rgba(241,245,249,0.95)" : "rgba(0,0,0,0.85)",
        nodes: [green, pink, amber],
        link: pink,
      };
    };

    const palette = getPalette();

    type Node = {
      x: number;
      y: number;
      z: number; // 0..1 depth
      c: string; // color
      vx: number;
      vy: number;
      r: number;
      swirl: number;
    };

    const area = (canvas.width * canvas.height) / (dpr * dpr);
    const particleCount = Math.max(120, Math.floor((area / 100000) * density * 100));

    const nodes: Node[] = [];
    const pick = <T,>(arr: T[]) => arr[Math.floor(Math.random() * arr.length)];

    for (let i = 0; i < particleCount; i++) {
      const z = Math.random();
      nodes.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        z,
        c: pick(palette.nodes),
        vx: (Math.random() - 0.5) * speed * dpr,
        vy: (Math.random() - 0.5) * speed * dpr,
        r: (1 + Math.random() * 1.6) * dpr,
        swirl: (Math.random() - 0.5) * 0.0012,
      });
    }

    const mouse = { x: canvas.width / 2, y: canvas.height / 3, active: false };
    const onMove = (e: MouseEvent) => {
      mouse.x = e.clientX * dpr;
      mouse.y = e.clientY * dpr;
      mouse.active = true;
    };
    window.addEventListener("mousemove", onMove);

    // Occasional pulse
    let pulseT = 0;
    let pulseR = 0;
    const resetPulse = () => {
      pulseT = 0;
      pulseR = 0;
    };

    const field = (x: number, y: number, t: number) => {
      // Smooth pseudo flow-field (no external noise dependency)
      const s = 0.0008;
      const a = Math.sin(y * s + t * 0.9);
      const b = Math.cos(x * s * 1.3 - t * 0.7);
      const c = Math.sin((x + y) * s * 0.7 + t * 0.4);
      const angle = a + b + c;
      return { fx: Math.cos(angle), fy: Math.sin(angle) };
    };

    const bgGradient = () => {
      const g = ctx.createRadialGradient(
        canvas.width * 0.5,
        canvas.height * 0.5,
        0,
        canvas.width * 0.5,
        canvas.height * 0.6,
        Math.max(canvas.width, canvas.height) * 0.8
      );
      if (isLight()) {
        g.addColorStop(0, palette.bg2);
        g.addColorStop(1, palette.bg1);
      } else {
        g.addColorStop(0, "rgba(0,0,0,0.9)");
        g.addColorStop(1, "rgba(0,0,0,0.6)");
      }
      return g;
    };

    const draw = () => {
      const t = (tRef.current += 0.006);

      // Trails
      ctx.globalCompositeOperation = "source-over";
      ctx.fillStyle = isLight() ? "rgba(255,255,255," + trailAlpha + ")" : "rgba(0,0,0," + trailAlpha + ")";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Aurora glow background overlay
      ctx.globalCompositeOperation = "lighter";
      const g = bgGradient();
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Pulse update
      if (pulseT <= 0) {
        if (Math.random() < 0.005) {
          pulseT = 1;
          pulseR = 0;
        }
      } else {
        pulseT *= 0.975; // fade
        pulseR += 14 * dpr; // grow
        const ring = ctx.createRadialGradient(mouse.x, mouse.y, Math.max(1, pulseR - 40 * dpr), mouse.x, mouse.y, pulseR + 1);
        const ringColor = hexToRGBA(palette.link, 0.07 * pulseT);
        ring.addColorStop(0, "rgba(0,0,0,0)");
        ring.addColorStop(1, ringColor);
        ctx.fillStyle = ring;
        ctx.beginPath();
        ctx.arc(mouse.x, mouse.y, pulseR + 2, 0, Math.PI * 2);
        ctx.fill();
        if (pulseT < 0.05) resetPulse();
      }

      // Nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        const f = field(n.x, n.y, t);
        const depth = 0.6 + n.z * 0.9;
        n.vx += f.fx * 0.08 * dpr * (0.7 + n.z * 0.6);
        n.vy += f.fy * 0.08 * dpr * (0.7 + n.z * 0.6);

        // swirl
        const cx = canvas.width * 0.5;
        const cy = canvas.height * 0.5;
        const dx = n.x - cx;
        const dy = n.y - cy;
        const ang = n.swirl * (1.6 - n.z);
        const cosA = Math.cos(ang);
        const sinA = Math.sin(ang);
        const rx = dx * cosA - dy * sinA;
        const ry = dx * sinA + dy * cosA;
        n.x = cx + rx + n.vx * (1.2 - n.z * 0.7);
        n.y = cy + ry + n.vy * (1.2 - n.z * 0.7);

        // mouse gravity well
        const mdx = mouse.x - n.x;
        const mdy = mouse.y - n.y;
        const md = Math.hypot(mdx, mdy) + 1e-2;
        if (mouse.active) {
          const pull = Math.min(1.2 / md, 0.0025) * dpr;
          n.vx += mdx * pull;
          n.vy += mdy * pull;
        }

        // wrap edges softly for continuity
        if (n.x < -50) n.x = canvas.width + 50;
        if (n.x > canvas.width + 50) n.x = -50;
        if (n.y < -50) n.y = canvas.height + 50;
        if (n.y > canvas.height + 50) n.y = -50;

        // draw glow node
        const radius = n.r * (1.0 + (1 - n.z) * 1.6);
        const glow = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, radius * 3);
        glow.addColorStop(0, hexToRGBA(n.c, 0.55 * depth));
        glow.addColorStop(0.6, hexToRGBA(n.c, 0.18 * depth));
        glow.addColorStop(1, hexToRGBA(n.c, 0));
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(n.x, n.y, radius * depth, 0, Math.PI * 2);
        ctx.fill();
      }

      // Links
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i];
          const b = nodes[j];
          const mz = (a.z + b.z) * 0.5;
          if (mz < 0.25) continue;
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d = Math.hypot(dx, dy);
          const maxD = 140 * dpr;
          if (d < maxD) {
            const alpha = (1 - d / maxD) * (0.3 + (1 - mz) * 0.4);
            ctx.strokeStyle = hexToRGBA(palette.link, alpha);
            ctx.lineWidth = (0.5 + (1 - mz) * 0.7) * dpr;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      rafRef.current = requestAnimationFrame(draw);
    };

    rafRef.current = requestAnimationFrame(draw);

    const mo = new MutationObserver(() => {
      // Recompute palette quickly on theme switch
      Object.assign(palette, getPalette());
    });
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMove);
      mo.disconnect();
    };
  }, [density, speed, trailAlpha, themeAware]);

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
  const full = c.length === 3 ? c.split("").map((ch) => ch + ch).join("") : c;
  const bigint = parseInt(full, 16);
  const r = (bigint >> 16) & 255;
  const g = (bigint >> 8) & 255;
  const b = bigint & 255;
  return `rgba(${r}, ${g}, ${b}, ${Math.max(0, Math.min(1, a))})`;
}
