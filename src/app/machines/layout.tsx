import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Machine Labs - 0xJerry\'s Lab',
  description: 'Cybersecurity machine labs featuring Hack The Box and TryHackMe platforms with detailed writeups and progress tracking.',
  keywords: 'cybersecurity, hacking, pentesting, hack the box, tryhackme, CTF, machines, writeups',
};

export default function MachinesLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
