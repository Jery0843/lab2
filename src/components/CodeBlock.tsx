'use client';

interface CodeBlockProps {
  children: React.ReactNode;
  className?: string;
}

export default function CodeBlock({ children, className }: CodeBlockProps) {
  return (
    <code className={`block overflow-x-auto ${className || ''}`}>
      {children}
    </code>
  );
}