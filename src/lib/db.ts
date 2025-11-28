// Cloudflare D1 Database Utilities

interface HTBStats {
  id?: number;
  machines_pwned: number;
  global_ranking: number;
  final_score: number;
  htb_rank: string;
  last_updated: string;
  created_at?: string;
}

interface CacheItem {
  cache_key: string;
  data: string;
  expires_at: string;
}

interface AdminLog {
  action: string;
  data?: string;
  ip_address?: string;
  user_agent?: string;
}

// Cloudflare D1 Database implementation using the API
import fetch from 'node-fetch';

class CloudflareD1Database {
  private apiToken: string;
  private accountId: string;
  private databaseId: string;
  private apiUrl: string;
  private isValid: boolean;

  constructor() {
    this.apiToken = process.env.CLOUDFLARE_API_TOKEN || '';
    this.accountId = process.env.CLOUDFLARE_ACCOUNT_ID || '';
    this.databaseId = process.env.CLOUDFLARE_DATABASE_ID || '';
    this.apiUrl = `https://api.cloudflare.com/client/v4/accounts/${this.accountId}/d1/database/${this.databaseId}/query`;
    
    // Validate required credentials
    this.isValid = !!(this.apiToken && this.accountId && this.databaseId);
    
    if (!this.isValid) {
      console.error('❌ CloudflareD1Database: Missing required credentials');
      console.error('Required: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_DATABASE_ID');
    } else {
      console.log('✅ CloudflareD1Database: Initialized with valid credentials');
      console.log('📍 Database ID:', this.databaseId);
      console.log('📍 Account ID:', this.accountId);
    }
  }

  async query(sql: string, params: unknown[] = []) {
    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ sql, params })
      });

      const data = await response.json() as any;

      if (!response.ok) {
        throw new Error(data.errors ? data.errors[0].message : 'Unknown error');
      }

      // Return the first result from the result array
      return data.result?.[0] || { results: [] };
    } catch (error) {
      console.error('Error querying the D1 database:', error);
      throw error;
    }
  }

  async prepare(query: string) {
    return {
      first: async () => {
        const result = await this.query(query);
        return result.results?.[0] || null;
      },
      all: async () => {
        const result = await this.query(query);
        return result.results || [];
      },
      run: async (params: unknown[] = []) => {
        const result = await this.query(query, params);
        return { 
          success: result.success !== false, 
          changes: result.meta?.changes || 0,
          meta: result.meta
        };
      },
      bind: (...params: unknown[]) => {
        return {
          first: async () => {
            const result = await this.query(query, params);
            return result.results?.[0] || null;
          },
          all: async () => {
            const result = await this.query(query, params);
            return result.results || [];
          },
          run: async () => {
            const result = await this.query(query, params);
            return { 
              success: result.success !== false, 
              changes: result.meta?.changes || 0,
              meta: result.meta
            };
          }
        };
      }
    };
  }
}

// Database connection helper - Use appropriate D1 connection method
export function getDatabase() {
  console.log('🔍 Attempting to get D1 database connection...');
  console.log('Environment:', process.env.NODE_ENV);
  console.log('Has API Token:', !!process.env.CLOUDFLARE_API_TOKEN);
  console.log('Has Account ID:', !!process.env.CLOUDFLARE_ACCOUNT_ID);
  console.log('Has Database ID:', !!process.env.CLOUDFLARE_DATABASE_ID);
  
  // Try to get D1 binding from various sources
  let db = null;
  
  // 1. Check for D1 binding in global scope (Cloudflare Workers runtime)
  if (typeof globalThis !== 'undefined') {
    // @ts-expect-error - D1 is provided by Cloudflare runtime
    db = globalThis.D1_DATABASE || globalThis.env?.D1_DATABASE;
    if (db) {
      console.log('✅ Found D1 database in globalThis (Cloudflare Workers)');
      return db;
    }
  }
  
  // 2. Check for D1 binding in self (Cloudflare Pages Functions)
  if (typeof self !== 'undefined' && 'D1_DATABASE' in self) {
    db = (self as any).D1_DATABASE;
    if (db) {
      console.log('✅ Found D1 database in self (Cloudflare Pages)');
      return db;
    }
  }
  
  // 3. Check for request context (Cloudflare Pages Functions with context)
  if (typeof globalThis !== 'undefined' && globalThis.process?.env?.CF_PAGES) {
    console.log('🌐 Detected Cloudflare Pages environment');
  }
  
  // 4. Fallback to API method for any environment with credentials
  const hasRequiredEnvVars = process.env.CLOUDFLARE_API_TOKEN && 
                            process.env.CLOUDFLARE_ACCOUNT_ID && 
                            process.env.CLOUDFLARE_DATABASE_ID;
  
  if (hasRequiredEnvVars) {
    console.log('🌐 Using Cloudflare D1 REST API for database operations');
    console.log('API URL will be:', `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${process.env.CLOUDFLARE_DATABASE_ID}/query`);
    return new CloudflareD1Database();
  }
  
  // 5. Final fallback - log detailed error information
  console.error('❌ D1 database not available');
  console.error('Current environment:', process.env.NODE_ENV || 'unknown');
  console.error('Platform detected:', typeof globalThis !== 'undefined' ? 'Node.js/Edge' : 'Unknown');
  console.error('Required environment variables:');
  console.error('- CLOUDFLARE_API_TOKEN:', process.env.CLOUDFLARE_API_TOKEN ? '[SET]' : '[MISSING]');
  console.error('- CLOUDFLARE_ACCOUNT_ID:', process.env.CLOUDFLARE_ACCOUNT_ID ? '[SET]' : '[MISSING]');
  console.error('- CLOUDFLARE_DATABASE_ID:', process.env.CLOUDFLARE_DATABASE_ID ? '[SET]' : '[MISSING]');
  
  console.error('\n🔧 Troubleshooting steps:');
  console.error('1. For Cloudflare Pages: Ensure D1 database is bound in Pages settings');
  console.error('2. For other platforms: Set all required environment variables');
  console.error('3. Verify API token has D1:edit permissions');
  console.error('4. Check database ID matches your D1 database');
  
  return null;
}

// HTB Stats operations
export class HTBStatsDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async getStats(): Promise<HTBStats | null> {
    if (!this.db) {
      console.warn('Database not available for HTB stats retrieval');
      return null;
    }
    
    try {
      console.log('🔍 HTBStatsDB: Fetching stats from database...');
      const prepared = await this.db.prepare('SELECT * FROM htb_stats WHERE id = 1');
      const result = await prepared.first();
      
      console.log('📊 HTBStatsDB: Raw result from database:', result);
      
      if (!result) {
        console.log('⚠️ HTBStatsDB: No stats found in database');
        return null;
      }
      
      const formattedResult = {
        id: result.id,
        machines_pwned: result.machines_pwned,
        global_ranking: result.global_ranking,
        final_score: result.final_score,
        htb_rank: result.htb_rank,
        last_updated: result.last_updated,
        created_at: result.created_at
      };
      
      console.log('✅ HTBStatsDB: Formatted result:', formattedResult);
      return formattedResult;
    } catch (error) {
      console.error('❌ HTBStatsDB: Error fetching HTB stats:', error);
      return null;
    }
  }

  async updateStats(stats: Omit<HTBStats, 'id' | 'created_at'>): Promise<HTBStats | null> {
    if (!this.db) {
      console.warn('Database not available for HTB stats update');
      return null;
    }
    
    try {
      console.log('🔄 HTBStatsDB: Updating stats with data:', stats);
      
      const prepared = await this.db.prepare(`
        INSERT OR REPLACE INTO htb_stats 
        (id, machines_pwned, global_ranking, final_score, htb_rank, last_updated)
        VALUES (1, ?, ?, ?, ?, ?)
      `);
      
      const bound = prepared.bind(
        stats.machines_pwned,
        stats.global_ranking,
        stats.final_score,
        stats.htb_rank,
        stats.last_updated
      );
      
      console.log('💾 HTBStatsDB: Executing database update...');
      const result = await bound.run();
      console.log('📊 HTBStatsDB: Update result:', result);

      if (result.success) {
        console.log('✅ HTBStatsDB: Update successful, fetching updated stats...');
        const updatedStats = await this.getStats();
        console.log('📈 HTBStatsDB: Updated stats from DB:', updatedStats);
        return updatedStats;
      }
      
      console.error('❌ HTBStatsDB: Update failed - result.success is false');
      return null;
    } catch (error) {
      console.error('❌ HTBStatsDB: Error updating HTB stats:', error);
      return null;
    }
  }
}

// Cache operations
export class CacheDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async get(key: string): Promise<any | null> {
    try {
      const prepared = await this.db.prepare('SELECT data FROM cache_data WHERE cache_key = ? AND expires_at > datetime("now")');
      const result = await prepared.bind(key).first();
      
      if (!result) return null;
      
      return JSON.parse(result.data);
    } catch (error) {
      console.error('Error getting cache:', error);
      return null;
    }
  }

  async set(key: string, data: any, ttlSeconds: number = 3600): Promise<boolean> {
    try {
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
      
      const prepared = await this.db.prepare(`
        INSERT OR REPLACE INTO cache_data 
        (cache_key, data, expires_at, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      `);
      
      const result = await prepared.bind(key, JSON.stringify(data), expiresAt).run();

      return result.success;
    } catch (error) {
      console.error('Error setting cache:', error);
      return false;
    }
  }

  async delete(key: string): Promise<boolean> {
    try {
      const prepared = await this.db.prepare('DELETE FROM cache_data WHERE cache_key = ?');
      const result = await prepared.bind(key).run();

      return result.success;
    } catch (error) {
      console.error('Error deleting cache:', error);
      return false;
    }
  }

  async cleanup(): Promise<boolean> {
    try {
      const prepared = await this.db.prepare('DELETE FROM cache_data WHERE expires_at <= datetime("now")');
      const result = await prepared.run();

      return result.success;
    } catch (error) {
      console.error('Error cleaning up cache:', error);
      return false;
    }
  }
}

// Admin logging
export class AdminLogDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async log(logData: AdminLog): Promise<boolean> {
    try {
      const prepared = await this.db.prepare(`
        INSERT INTO admin_logs 
        (action, data, ip_address, user_agent, timestamp)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      `);
      
      const result = await prepared.bind(
        logData.action,
        logData.data || null,
        logData.ip_address || null,
        logData.user_agent || null
      ).run();

      return result.success;
    } catch (error) {
      console.error('Error logging admin action:', error);
      return false;
    }
  }

  async getLogs(limit: number = 50): Promise<any[]> {
    try {
      const prepared = await this.db.prepare('SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT ?');
      const result = await prepared.bind(limit).all();

      return result || [];
    } catch (error) {
      console.error('Error getting admin logs:', error);
      return [];
    }
  }
}

// HTB Machines operations
export class HTBMachinesDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async getAllMachines(): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for machines retrieval');
      return [];
    }
    
    try {
      // Order by completion date (latest first), then by created_at for non-completed machines
      const prepared = await this.db.prepare(`
        SELECT * FROM htb_machines 
        ORDER BY 
          CASE WHEN date_completed IS NOT NULL THEN date_completed END DESC,
          CASE WHEN date_completed IS NULL THEN created_at END DESC
      `);
      const result = await prepared.all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching HTB machines:', error);
      return [];
    }
  }

  async getMachine(id: string): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for machine retrieval');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM htb_machines WHERE id = ?');
      const result = await prepared.bind(id).first();
      
      return result || null;
    } catch (error) {
      console.error('Error fetching HTB machine:', error);
      return null;
    }
  }

  async createMachine(machine: any): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for machine creation');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare(`
        INSERT INTO htb_machines 
        (id, name, os, difficulty, status, is_active, password, summary, date_completed, tags, writeup, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `);
      
      const result = await prepared.bind(
        machine.id,
        machine.name,
        machine.os,
        machine.difficulty,
        machine.status,
        typeof machine.is_active === 'number' ? machine.is_active : (machine.is_active ? 1 : 0),
        machine.password || null,
        machine.summary || null,
        machine.date_completed,
        machine.tags,
        machine.writeup
      ).run();

      if (result.success) {
        return await this.getMachine(machine.id);
      }
      
      return null;
    } catch (error) {
      console.error('Error creating HTB machine:', error);
      return null;
    }
  }

  async updateMachine(id: string, machine: any): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for machine update');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare(`
        UPDATE htb_machines 
        SET name = ?, os = ?, difficulty = ?, status = ?, is_active = ?, password = ?, summary = ?, date_completed = ?, 
            tags = ?, writeup = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `);
      
      const result = await prepared.bind(
        machine.name,
        machine.os,
        machine.difficulty,
        machine.status,
        typeof machine.is_active === 'number' ? machine.is_active : (machine.is_active ? 1 : 0),
        machine.password || null,
        machine.summary || null,
        machine.date_completed,
        machine.tags,
        machine.writeup,
        id
      ).run();

      if (result.success) {
        return await this.getMachine(id);
      }
      
      return null;
    } catch (error) {
      console.error('Error updating HTB machine:', error);
      return null;
    }
  }

  async deleteMachine(id: string): Promise<boolean> {
    if (!this.db) {
      console.warn('Database not available for machine deletion');
      return false;
    }
    
    try {
      const prepared = await this.db.prepare('DELETE FROM htb_machines WHERE id = ?');
      const result = await prepared.bind(id).run();

      return result.success;
    } catch (error) {
      console.error('Error deleting HTB machine:', error);
      return false;
    }
  }

  async getMachinesByStatus(status: string): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for machines by status retrieval');
      return [];
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM htb_machines WHERE status = ? ORDER BY created_at DESC');
      const result = await prepared.bind(status).all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching machines by status:', error);
      return [];
    }
  }

  async getMachinesByDifficulty(difficulty: string): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for machines by difficulty retrieval');
      return [];
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM htb_machines WHERE difficulty = ? ORDER BY created_at DESC');
      const result = await prepared.bind(difficulty).all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching machines by difficulty:', error);
      return [];
    }
  }

  async getStats(): Promise<any> {
    if (!this.db) {
      console.warn('Database not available for stats retrieval');
      return {
        total: 0,
        completed: 0,
        inProgress: 0,
        easy: 0,
        medium: 0,
        hard: 0
      };
    }
    
    try {
      const [totalPrep, completedPrep, inProgressPrep, easyPrep, mediumPrep, hardPrep] = await Promise.all([
        this.db.prepare('SELECT COUNT(*) as count FROM htb_machines'),
        this.db.prepare('SELECT COUNT(*) as count FROM htb_machines WHERE status = "Completed"'),
        this.db.prepare('SELECT COUNT(*) as count FROM htb_machines WHERE status = "In Progress"'),
        this.db.prepare('SELECT COUNT(*) as count FROM htb_machines WHERE difficulty = "Easy"'),
        this.db.prepare('SELECT COUNT(*) as count FROM htb_machines WHERE difficulty = "Medium"'),
        this.db.prepare('SELECT COUNT(*) as count FROM htb_machines WHERE difficulty = "Hard"')
      ]);
      
      const [total, completed, inProgress, easy, medium, hard] = await Promise.all([
        totalPrep.first(),
        completedPrep.first(),
        inProgressPrep.first(),
        easyPrep.first(),
        mediumPrep.first(),
        hardPrep.first()
      ]);

      return {
        total: total?.count || 0,
        completed: completed?.count || 0,
        inProgress: inProgress?.count || 0,
        easy: easy?.count || 0,
        medium: medium?.count || 0,
        hard: hard?.count || 0
      };
    } catch (error) {
      console.error('Error fetching machine stats:', error);
      return {
        total: 0,
        completed: 0,
        inProgress: 0,
        easy: 0,
        medium: 0,
        hard: 0
      };
    }
  }
}

// THM Rooms operations
export class THMRoomsDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async getAllRooms(): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for THM rooms retrieval');
      return [];
    }
    
    try {
      // Order by completion date (latest first), then by created_at for non-completed rooms
      const prepared = await this.db.prepare(`
        SELECT * FROM thm_rooms 
        ORDER BY 
          CASE WHEN date_completed IS NOT NULL THEN date_completed END DESC,
          CASE WHEN date_completed IS NULL THEN created_at END DESC
      `);
      const result = await prepared.all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching THM rooms:', error);
      return [];
    }
  }

  async getRoom(id: string): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for THM room retrieval');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM thm_rooms WHERE id = ?');
      const result = await prepared.bind(id).first();
      
      return result || null;
    } catch (error) {
      console.error('Error fetching THM room:', error);
      return null;
    }
  }

  async createRoom(room: any): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for THM room creation');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare(`
        INSERT INTO thm_rooms 
        (id, name, difficulty, status, date_completed, tags, description, writeup, room_code, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `);
      
      const result = await prepared.bind(
        room.id,
        room.title || room.name, // Use title if provided, fallback to name
        room.difficulty,
        room.status,
        room.date_completed,
        room.tags,
        room.description || `TryHackMe room: ${room.title || room.name}`,
        room.writeup,
        room.room_code || room.roomCode || room.id
      ).run();

      if (result.success) {
        return await this.getRoom(room.id);
      }
      
      return null;
    } catch (error) {
      console.error('Error creating THM room:', error);
      return null;
    }
  }

  async updateRoom(id: string, room: any): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for THM room update');
      return null;
    }
    
    try {
      // First, get the existing room to avoid null constraint errors
      const existingRoom = await this.getRoom(id);
      if (!existingRoom) {
        console.error('Room not found for update:', id);
        return null;
      }

      // Merge existing data with updates, ensuring required fields are not null
      const updateData = {
        name: room.title || room.name || existingRoom.name,
        difficulty: room.difficulty || existingRoom.difficulty,
        status: room.status || existingRoom.status,
        date_completed: room.date_completed !== undefined ? room.date_completed : existingRoom.date_completed,
        tags: room.tags !== undefined ? room.tags : existingRoom.tags,
        description: room.description || existingRoom.description || `TryHackMe room: ${room.title || room.name || existingRoom.name}`,
        writeup: room.writeup !== undefined ? room.writeup : existingRoom.writeup,
        room_code: room.room_code !== undefined ? room.room_code : (room.roomCode !== undefined ? room.roomCode : existingRoom.room_code)
      };

      const prepared = await this.db.prepare(`
        UPDATE thm_rooms 
        SET name = ?, difficulty = ?, status = ?, date_completed = ?, 
            tags = ?, description = ?, writeup = ?, room_code = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `);
      
      const result = await prepared.bind(
        updateData.name,
        updateData.difficulty,
        updateData.status,
        updateData.date_completed,
        updateData.tags,
        updateData.description,
        updateData.writeup,
        updateData.room_code,
        id
      ).run();

      if (result.success) {
        return await this.getRoom(id);
      }
      
      return null;
    } catch (error) {
      console.error('Error updating THM room:', error);
      return null;
    }
  }

  async deleteRoom(id: string): Promise<boolean> {
    if (!this.db) {
      console.warn('Database not available for THM room deletion');
      return false;
    }
    
    try {
      const prepared = await this.db.prepare('DELETE FROM thm_rooms WHERE id = ?');
      const result = await prepared.bind(id).run();

      return result.success;
    } catch (error) {
      console.error('Error deleting THM room:', error);
      return false;
    }
  }

  async getRoomsByStatus(status: string): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for THM rooms by status retrieval');
      return [];
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM thm_rooms WHERE status = ? ORDER BY created_at DESC');
      const result = await prepared.bind(status).all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching THM rooms by status:', error);
      return [];
    }
  }

  async getRoomsByDifficulty(difficulty: string): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for THM rooms by difficulty retrieval');
      return [];
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM thm_rooms WHERE difficulty = ? ORDER BY created_at DESC');
      const result = await prepared.bind(difficulty).all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching THM rooms by difficulty:', error);
      return [];
    }
  }

  async getStats(): Promise<any> {
    if (!this.db) {
      console.warn('Database not available for THM stats retrieval');
      return {
        total: 0,
        completed: 0,
        inProgress: 0,
        easy: 0,
        medium: 0,
        hard: 0
      };
    }
    
    try {
      const [totalPrep, completedPrep, inProgressPrep, easyPrep, mediumPrep, hardPrep] = await Promise.all([
        this.db.prepare('SELECT COUNT(*) as count FROM thm_rooms'),
        this.db.prepare('SELECT COUNT(*) as count FROM thm_rooms WHERE status = "Completed"'),
        this.db.prepare('SELECT COUNT(*) as count FROM thm_rooms WHERE status = "In Progress"'),
        this.db.prepare('SELECT COUNT(*) as count FROM thm_rooms WHERE difficulty = "Easy"'),
        this.db.prepare('SELECT COUNT(*) as count FROM thm_rooms WHERE difficulty = "Medium"'),
        this.db.prepare('SELECT COUNT(*) as count FROM thm_rooms WHERE difficulty = "Hard"')
      ]);
      
      const [total, completed, inProgress, easy, medium, hard] = await Promise.all([
        totalPrep.first(),
        completedPrep.first(),
        inProgressPrep.first(),
        easyPrep.first(),
        mediumPrep.first(),
        hardPrep.first()
      ]);

      return {
        total: total?.count || 0,
        completed: completed?.count || 0,
        inProgress: inProgress?.count || 0,
        easy: easy?.count || 0,
        medium: medium?.count || 0,
        hard: hard?.count || 0
      };
    } catch (error) {
      console.error('Error fetching THM room stats:', error);
      return {
        total: 0,
        completed: 0,
        inProgress: 0,
        easy: 0,
        medium: 0,
        hard: 0
      };
    }
  }
}

// THM Stats operations (profile summary)
export class THMStatsDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async getStats(): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for THM profile stats retrieval');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM thm_stats WHERE id = 1');
      const result = await prepared.first();
      
      if (!result) return null;
      
      return {
        id: result.id,
        thm_rank: result.thm_rank,
        global_ranking: result.global_ranking,
        rooms_completed: result.rooms_completed,
        streak: result.streak,
        badges: result.badges,
        total_points: result.total_points,
        last_updated: result.last_updated,
        created_at: result.created_at
      };
    } catch (error) {
      console.error('Error fetching THM profile stats:', error);
      return null;
    }
  }

  async updateStats(stats: any): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for THM profile stats update');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare(`
        INSERT OR REPLACE INTO thm_stats 
        (id, thm_rank, global_ranking, rooms_completed, streak, badges, total_points, last_updated)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?)
      `);
      
      const bound = prepared.bind(
        stats.thm_rank,
        stats.global_ranking || 0,
        stats.rooms_completed,
        stats.streak,
        stats.badges || 0,
        stats.total_points || 0,
        stats.last_updated
      );
      
      const result = await bound.run();

      if (result.success) {
        return await this.getStats();
      }
      
      return null;
    } catch (error) {
      console.error('Error updating THM profile stats:', error);
      return null;
    }
  }
}

// CTF Writeups operations
export class CTFWriteupsDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async getAllWriteups(): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for CTF writeups retrieval');
      return [];
    }
    
    try {
      const prepared = await this.db.prepare(`
        SELECT * FROM ctf_writeups 
        ORDER BY 
          CASE WHEN date_completed IS NOT NULL THEN date_completed END DESC,
          CASE WHEN date_completed IS NULL THEN created_at END DESC
      `);
      const result = await prepared.all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching CTF writeups:', error);
      return [];
    }
  }

  async getWriteup(id: string): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for CTF writeup retrieval');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM ctf_writeups WHERE id = ?');
      const result = await prepared.bind(id).first();
      
      return result || null;
    } catch (error) {
      console.error('Error fetching CTF writeup:', error);
      return null;
    }
  }

  async createWriteup(writeup: any): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for CTF writeup creation');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare(`
        INSERT INTO ctf_writeups 
        (id, title, slug, ctf_name, category, difficulty, points, status, is_active, password, date_completed, tags, writeup, summary, flag, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `);
      
      const result = await prepared.bind(
        writeup.id,
        writeup.title,
        writeup.slug,
        writeup.ctf_name,
        writeup.category,
        writeup.difficulty,
        writeup.points || 0,
        writeup.status,
        typeof writeup.is_active === 'number' ? writeup.is_active : (writeup.is_active ? 1 : 0),
        writeup.password || null,
        writeup.date_completed,
        writeup.tags,
        writeup.writeup,
        writeup.summary || null,
        writeup.flag || null
      ).run();

      if (result.success) {
        return await this.getWriteup(writeup.id);
      }
      
      return null;
    } catch (error) {
      console.error('Error creating CTF writeup:', error);
      return null;
    }
  }

  async updateWriteup(id: string, writeup: any): Promise<any | null> {
    if (!this.db) {
      console.warn('Database not available for CTF writeup update');
      return null;
    }
    
    try {
      const prepared = await this.db.prepare(`
        UPDATE ctf_writeups 
        SET title = ?, slug = ?, ctf_name = ?, category = ?, difficulty = ?, points = ?, status = ?, is_active = ?, password = ?, 
            date_completed = ?, tags = ?, writeup = ?, summary = ?, flag = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `);
      
      const result = await prepared.bind(
        writeup.title,
        writeup.slug,
        writeup.ctf_name,
        writeup.category,
        writeup.difficulty,
        writeup.points || 0,
        writeup.status,
        typeof writeup.is_active === 'number' ? writeup.is_active : (writeup.is_active ? 1 : 0),
        writeup.password || null,
        writeup.date_completed,
        writeup.tags,
        writeup.writeup,
        writeup.summary || null,
        writeup.flag || null,
        id
      ).run();

      if (result.success) {
        return await this.getWriteup(id);
      }
      
      return null;
    } catch (error) {
      console.error('Error updating CTF writeup:', error);
      return null;
    }
  }

  async deleteWriteup(id: string): Promise<boolean> {
    if (!this.db) {
      console.warn('Database not available for CTF writeup deletion');
      return false;
    }
    
    try {
      const prepared = await this.db.prepare('DELETE FROM ctf_writeups WHERE id = ?');
      const result = await prepared.bind(id).run();

      return result.success;
    } catch (error) {
      console.error('Error deleting CTF writeup:', error);
      return false;
    }
  }

  async getWriteupsByCategory(category: string): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for CTF writeups by category retrieval');
      return [];
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM ctf_writeups WHERE category = ? ORDER BY created_at DESC');
      const result = await prepared.bind(category).all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching CTF writeups by category:', error);
      return [];
    }
  }

  async getWriteupsByCTF(ctfName: string): Promise<any[]> {
    if (!this.db) {
      console.warn('Database not available for CTF writeups by CTF name retrieval');
      return [];
    }
    
    try {
      const prepared = await this.db.prepare('SELECT * FROM ctf_writeups WHERE ctf_name = ? ORDER BY created_at DESC');
      const result = await prepared.bind(ctfName).all();
      
      return result || [];
    } catch (error) {
      console.error('Error fetching CTF writeups by CTF name:', error);
      return [];
    }
  }

  async getStats(): Promise<any> {
    if (!this.db) {
      console.warn('Database not available for CTF stats retrieval');
      return {
        total: 0,
        completed: 0,
        inProgress: 0,
        easy: 0,
        medium: 0,
        hard: 0,
        categories: {}
      };
    }
    
    try {
      const [totalPrep, completedPrep, inProgressPrep, easyPrep, mediumPrep, hardPrep, categoriesPrep] = await Promise.all([
        this.db.prepare('SELECT COUNT(*) as count FROM ctf_writeups'),
        this.db.prepare('SELECT COUNT(*) as count FROM ctf_writeups WHERE status = "Completed"'),
        this.db.prepare('SELECT COUNT(*) as count FROM ctf_writeups WHERE status = "In Progress"'),
        this.db.prepare('SELECT COUNT(*) as count FROM ctf_writeups WHERE difficulty = "Easy"'),
        this.db.prepare('SELECT COUNT(*) as count FROM ctf_writeups WHERE difficulty = "Medium"'),
        this.db.prepare('SELECT COUNT(*) as count FROM ctf_writeups WHERE difficulty = "Hard"'),
        this.db.prepare('SELECT category, COUNT(*) as count FROM ctf_writeups GROUP BY category')
      ]);
      
      const [total, completed, inProgress, easy, medium, hard, categoriesResult] = await Promise.all([
        totalPrep.first(),
        completedPrep.first(),
        inProgressPrep.first(),
        easyPrep.first(),
        mediumPrep.first(),
        hardPrep.first(),
        categoriesPrep.all()
      ]);

      const categories: { [key: string]: number } = {};
      if (categoriesResult) {
        categoriesResult.forEach((row: any) => {
          categories[row.category] = row.count;
        });
      }

      return {
        total: total?.count || 0,
        completed: completed?.count || 0,
        inProgress: inProgress?.count || 0,
        easy: easy?.count || 0,
        medium: medium?.count || 0,
        hard: hard?.count || 0,
        categories
      };
    } catch (error) {
      console.error('Error fetching CTF writeup stats:', error);
      return {
        total: 0,
        completed: 0,
        inProgress: 0,
        easy: 0,
        medium: 0,
        hard: 0,
        categories: {}
      };
    }
  }
}

// Default export with all utilities
export default {
  HTBStatsDB,
  CacheDB,
  AdminLogDB,
  HTBMachinesDB,
  THMRoomsDB,
  THMStatsDB,
  CTFWriteupsDB,
  getDatabase
};
