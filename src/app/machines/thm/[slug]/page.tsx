import { Metadata } from 'next';
import { notFound } from 'next/navigation';
import thmRoomsData from '@/data/thm-rooms.json';
import { THMRoomsDB } from '@/lib/db';
import { generateMachineMetadata } from '@/lib/seo-helpers';
import THMRoomPage from './thm-room-page';

interface THMRoomPageProps {
  params: Promise<{ slug: string }>;
}

// Generate static params for all THM rooms
export async function generateStaticParams() {
  try {
    // Always start with static data
    const staticRooms = thmRoomsData
      .filter(room => room.slug && typeof room.slug === 'string')
      .map((room) => ({
        slug: room.slug,
      }));
    
    console.log('Generated static params for THM rooms:', staticRooms);
    
    // Return static params only to avoid database issues during build
    return staticRooms;
  } catch (error) {
    console.error('Error generating THM static params:', error);
    // Fallback to hardcoded room slugs if all else fails
    return [
      { slug: 'blue' },
      { slug: 'basic-pentesting' },
      { slug: 'vulnversity' },
      { slug: 'kenobi' },
      { slug: 'mr-robot-ctf' }
    ];
  }
}

// Generate metadata for each THM room page
export async function generateMetadata({ params }: THMRoomPageProps): Promise<Metadata> {
  const resolvedParams = await params;
  const { slug } = resolvedParams;
  
  try {
    // First, try to find in static data
    let room = thmRoomsData.find(r => r.slug === slug);
    
    // If not found in static data, try database
    if (!room) {
      try {
        const roomsDB = new THMRoomsDB();
        const dbRoom = await roomsDB.getRoom(slug);
        if (dbRoom) {
          room = dbRoom;
        }
      } catch (error) {
        console.warn('Database not available for THM metadata, using static data only:', error);
      }
    }

    if (!room) {
      return {
        title: 'THM Room Not Found | 0xJerry\'s Lab',
        description: 'The requested TryHackMe room writeup could not be found.',
      };
    }

    // Convert THM room to machine format for metadata generation
    const machineFormat = {
      id: room.id || slug,
      name: room.title || slug,
      os: 'Linux', // Default OS for THM rooms
      slug: room.slug || slug,
      difficulty: room.difficulty || 'Medium',
      status: room.status || 'Active',
      dateCompleted: room.dateCompleted || null,
      tags: Array.isArray(room.tags) ? room.tags : (room.tags ? [room.tags] : []),
      writeup: room.writeup || null
    };
    
    const metadata = generateMachineMetadata(machineFormat);    // Customize for THM
    return {
      ...metadata,
      title: metadata.title?.replace('HTB', 'THM'),
      description: metadata.description?.replace('Hack The Box', 'TryHackMe'),
    };
  } catch (error) {
    console.error('Error generating THM metadata:', error);
    return {
      title: 'THM Room | 0xJerry\'s Lab',
      description: 'TryHackMe room writeup and walkthrough.',
    };
  }
}

export default async function THMRoomPageWrapper({ params }: THMRoomPageProps) {
  const resolvedParams = await params;
  const { slug } = resolvedParams;
  
  console.log('Looking for THM room with slug:', slug);
  console.log('Available THM rooms:', thmRoomsData.map(r => r.slug));
  
  try {
    // First, try to find in static data
    let room = thmRoomsData.find(r => r.slug === slug);
    
    if (room) {
      console.log('Found THM room in static data:', room.title);
      return <THMRoomPage room={room} />;
    }
    
    // If not found in static data, try database
    try {
      const roomsDB = new THMRoomsDB();
      const dbRoom = await roomsDB.getRoom(slug);
      if (dbRoom) {
        console.log('Found THM room in database:', dbRoom.title);
        return <THMRoomPage room={dbRoom} />;
      }
    } catch (dbError) {
      console.warn('Database lookup failed for THM room:', dbError);
    }

    console.log('THM room not found anywhere, slug:', slug);
    notFound();
  } catch (error) {
    console.error('Error loading THM room page:', error);
    notFound();
  }
}
