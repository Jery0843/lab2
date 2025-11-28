import { Metadata } from 'next';
import { notFound } from 'next/navigation';
import machinesData from '@/data/machines.json';
import { HTBMachinesDB, getDatabase } from '@/lib/db';
import { generateMachineMetadata } from '@/lib/seo-helpers';
import MachinePage from './machine-page';
import { parseTags } from '@/lib/utils';

interface MachinePageProps {
  params: Promise<{ slug: string }>;
}

// Generate static params for all machines
export async function generateStaticParams() {
  try {
    // Always start with static data
    const staticMachines = machinesData
      .filter(machine => machine.id && typeof machine.id === 'string')
      .map((machine) => ({
        slug: machine.id,
      }));
    
    console.log('Generated static params:', staticMachines);
    
    // Return static params only to avoid database issues during build
    return staticMachines;
  } catch (error) {
    console.error('Error generating static params:', error);
    // Fallback to hardcoded machine IDs if all else fails
    return [
      { slug: 'lame' },
      { slug: 'legacy' },
      { slug: 'devel' },
      { slug: 'beep' },
      { slug: 'optimum' }
    ];
  }
}

// Generate metadata for each machine page
export async function generateMetadata({ params }: MachinePageProps): Promise<Metadata> {
  const resolvedParams = await params;
  const { slug } = resolvedParams;
  
  try {
    // First, try to find in static data
    let machine = machinesData.find(m => m.id === slug);
    
    // If not found in static data, try database
    if (!machine) {
      try {
        const machinesDB = new HTBMachinesDB();
        const dbMachine = await machinesDB.getMachine(slug);
        if (dbMachine) {
          machine = dbMachine;
        }
      } catch (error) {
        console.warn('Database not available for metadata, using static data only:', error);
      }
    }

    if (!machine) {
      return {
        title: 'Machine Not Found | 0xJerry\'s Lab',
        description: 'The requested machine writeup could not be found.',
      };
    }

    return generateMachineMetadata(machine);
  } catch (error) {
    console.error('Error generating metadata:', error);
    return {
      title: 'Machine | 0xJerry\'s Lab',
      description: 'Hack The Box machine writeup and walkthrough.',
    };
  }
}

async function getSimilarMachines(machine: any) {
  const tagsArray = parseTags(machine.tags);
  const params = new URLSearchParams({
    id: machine.id,
    os: machine.os,
    difficulty: machine.difficulty,
    tags: tagsArray.join(','),
  });

  // In a server component, we can call the API route's logic directly
  // or fetch from the absolute URL. Let's call the logic directly for performance.
  try {
    const db = getDatabase();
    if (!db) {
      // Fallback to static data if DB is not available
      const allMachines = machinesData;
      return allMachines.filter(m => m.id !== machine.id).slice(0, 3);
    }

    const machinesDB = new HTBMachinesDB(db);
    const allMachines = await machinesDB.getAllMachines();

    const related = allMachines
      .filter(m => m.id !== machine.id)
      .map(m => {
        const relatedTags = parseTags(m.tags);
        let score = 0;
        const tagMatches = tagsArray.filter(tag => 
          relatedTags.some(relatedTag => 
            relatedTag.toLowerCase().includes(tag.toLowerCase()) || 
            tag.toLowerCase().includes(relatedTag.toLowerCase())
          )
        ).length;
        score += tagMatches * 3;
        if (m.os === machine.os) score += 2;
        if (m.difficulty === machine.difficulty) score += 1;
        return { ...m, score };
      })
      .filter(m => m.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3);

    return related;

  } catch (error) {
    console.error('Error fetching similar machines on server:', error);
    return [];
  }
}

export default async function MachinePageWrapper({ params }: MachinePageProps) {
  const resolvedParams = await params;
  const { slug } = resolvedParams;
  
  console.log('Looking for machine with slug:', slug);
  console.log('Available machines:', machinesData.map(m => m.id));
  
  try {
    // First, try to find in static data
    let machine = machinesData.find(m => m.id === slug);
    
    if (machine) {
      console.log('Found machine in static data:', machine.name);
      // Fetch similar machines on the server
      const similarMachines = await getSimilarMachines(machine);
      return <MachinePage machine={machine} initialRelatedMachines={similarMachines} />;
    }
    
    // If not found in static data, try database
    try {
      const machinesDB = new HTBMachinesDB();
      const dbMachine = await machinesDB.getMachine(slug);
      if (dbMachine) {
        console.log('Found machine in database:', dbMachine.name);
        const similarMachines = await getSimilarMachines(dbMachine);
        return <MachinePage machine={dbMachine} initialRelatedMachines={similarMachines} />;
      }
    } catch (dbError) {
      console.warn('Database lookup failed:', dbError);
    }

    console.log('Machine not found anywhere, slug:', slug);
    notFound();
  } catch (error) {
    console.error('Error loading machine page:', error);
    notFound();
  }
}