import { ReactNode } from 'react';
import { generateMachineStructuredData } from '@/lib/seo-helpers';
import machinesData from '@/data/machines.json';

interface Machine {
  id: string;
  name: string;
  os: string;
  difficulty: string;
  status: string;
  dateCompleted: string | null;
  tags: string[] | string;
  writeup: string | null;
}

interface LayoutProps {
  children: ReactNode;
  params: Promise<{ slug: string }>;
}

export default async function MachineLayout({ children, params }: LayoutProps) {
  const { slug } = await params;
  
  // Find the machine
  const machine = machinesData.find(m => m.id === slug) as Machine | undefined;
  
  if (!machine) {
    return <>{children}</>;
  }

  const structuredData = generateMachineStructuredData(machine);

  return (
    <>
      {/* JSON-LD Structured Data */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify(structuredData)
        }}
      />
      {children}
    </>
  );
}
