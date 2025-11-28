import { NextRequest, NextResponse } from 'next/server';
import { THMRoomsDB } from '@/lib/db';
import thmRoomsData from '@/data/thm-rooms.json';

// Helper function to generate unique ID
function generateRoomId(title: string): string {
  return title.toLowerCase()
    .replace(/[^a-z0-9]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

// GET: Fetch all THM rooms
export async function GET() {
  try {
    const roomsDB = new THMRoomsDB();
    const rooms = await roomsDB.getAllRooms();
    
    // If no rooms in database, return fallback data
    if (!rooms || rooms.length === 0) {
      console.log('No THM rooms in database, returning fallback data');
      return NextResponse.json(thmRoomsData);
    }
    
    // Map database fields to expected API format
    const mappedRooms = rooms.map(room => ({
      id: room.id,
      title: room.name, // Map 'name' column to 'title' for frontend
      name: room.name,
      difficulty: room.difficulty,
      status: room.status,
      date_completed: room.date_completed,
      dateCompleted: room.date_completed, // Add camelCase version
      tags: typeof room.tags === 'string' ? room.tags.split(',').filter((tag: string) => tag.trim()) : (Array.isArray(room.tags) ? room.tags : []),
      writeup: room.writeup,
      description: room.description,
      roomCode: room.room_code, // Add camelCase version
      room_code: room.room_code,
      // Add fallbacks for fields that don't exist in actual database
      slug: room.id, // Use ID as slug fallback
      url: `https://tryhackme.com/room/${room.room_code || room.id}`,
      points: 100, // Default points since not in database
      created_at: room.created_at,
      updated_at: room.updated_at
    }));
    
    console.log(`Fetched ${mappedRooms.length} THM rooms from database`);
    return NextResponse.json(mappedRooms);
  } catch (error) {
    console.error('Error fetching THM rooms:', error);
    
    // Return fallback data if database fails
    return NextResponse.json(thmRoomsData, {
      headers: {
        'X-Fallback': 'true'
      }
    });
  }
}

// POST: Create new THM room
export async function POST(request: NextRequest) {
  try {
    const roomData = await request.json();
    
    // Validate required fields
    if (!roomData.title || !roomData.difficulty) {
      return NextResponse.json(
        { error: 'Title and difficulty are required' },
        { status: 400 }
      );
    }
    
    // Generate ID if not provided
    if (!roomData.id) {
      roomData.id = generateRoomId(roomData.title);
    }
    
    // Generate slug if not provided
    if (!roomData.slug) {
      roomData.slug = roomData.id;
    }
    
    // Set defaults
    const newRoom = {
      id: roomData.id,
      title: roomData.title,
      slug: roomData.slug,
      difficulty: roomData.difficulty,
      status: roomData.status || 'In Progress',
      tags: Array.isArray(roomData.tags) ? roomData.tags.join(',') : (roomData.tags || ''),
      writeup: roomData.writeup || null,
      url: roomData.url || `https://tryhackme.com/room/${roomData.slug}`,
      room_code: roomData.roomCode || roomData.room_code || roomData.slug,
      points: roomData.points || 100,
      date_completed: roomData.dateCompleted || roomData.date_completed || null,
    };
    
    const roomsDB = new THMRoomsDB();
    const createdRoom = await roomsDB.createRoom(newRoom);
    
    if (!createdRoom) {
      return NextResponse.json(
        { error: 'Failed to create room in database' },
        { status: 500 }
      );
    }
    
    console.log('Created THM room:', createdRoom.id);
    return NextResponse.json({ room: createdRoom }, { status: 201 });
  } catch (error) {
    console.error('Error creating THM room:', error);
    return NextResponse.json(
      { error: 'Internal server error', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}

// PUT: Update existing THM room
export async function PUT(request: NextRequest) {
  try {
    const roomData = await request.json();
    console.log('Updating THM room with data:', roomData);
    
    if (!roomData.id) {
      return NextResponse.json(
        { error: 'Room ID is required for updates' },
        { status: 400 }
      );
    }
    
    const roomsDB = new THMRoomsDB();
    const updatedRoom = await roomsDB.updateRoom(roomData.id, roomData);
    
    if (!updatedRoom) {
      return NextResponse.json(
        { error: 'Failed to update room or room not found' },
        { status: 404 }
      );
    }
    
    console.log('Updated THM room:', updatedRoom.id);
    return NextResponse.json({ room: updatedRoom });
  } catch (error) {
    console.error('Error updating THM room:', error);
    return NextResponse.json(
      { error: 'Internal server error', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}

// DELETE: Remove THM room
export async function DELETE(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const roomId = url.searchParams.get('id');
    
    if (!roomId) {
      return NextResponse.json(
        { error: 'Room ID is required' },
        { status: 400 }
      );
    }
    
    const roomsDB = new THMRoomsDB();
    const success = await roomsDB.deleteRoom(roomId);
    
    if (!success) {
      return NextResponse.json(
        { error: 'Failed to delete room or room not found' },
        { status: 404 }
      );
    }
    
    console.log('Deleted THM room:', roomId);
    return NextResponse.json({ message: 'Room deleted successfully' });
  } catch (error) {
    console.error('Error deleting THM room:', error);
    return NextResponse.json(
      { error: 'Internal server error', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
