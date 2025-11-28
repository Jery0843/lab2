'use client';

import { useState, useEffect } from 'react';

interface Heading {
  id: string;
  text: string;
  level: number;
}

export default function TableOfContents({ content }: { content: string }) {
  const [headings, setHeadings] = useState<Heading[]>([]);

  useEffect(() => {
    const foundHeadings: Heading[] = [];
    const matches = content.matchAll(/^(#{1,3})\s+(.*)/gm);
    for (const match of matches) {
      const level = match[1].length;
      const text = match[2];
      const id = text.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]+/g, '');
      foundHeadings.push({ id, text, level });
    }
    setHeadings(foundHeadings);
  }, [content]);

  if (headings.length === 0) {
    return null;
  }

  return (
    <div id="toc-container" className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 max-h-[calc(100vh-7rem)] overflow-y-auto">
      <h3 className="font-cyber text-xl text-cyber-purple mb-4 !mt-0">ON THIS PAGE</h3>
      <ul className="!pl-0">
        {headings.map(heading => (
          <li key={heading.id} style={{ marginLeft: `${(heading.level - 1) * 1}rem` }} className="mb-2">
            <a
              href={`#${heading.id}`}
              className="text-sm text-gray-400 hover:text-cyber-purple transition-colors break-words"
              onClick={(e) => {
                e.preventDefault();
                document.getElementById(heading.id)?.scrollIntoView({ behavior: 'smooth' });
              }}
            >
              {heading.text}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}