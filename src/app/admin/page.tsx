import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import { getDatabase } from '@/lib/db';
import AdminDashboardClient from './AdminDashboardClient';

// Server-side authentication check - cannot be bypassed by client
async function validateServerAuth() {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get('admin_session')?.value;
  
  if (!sessionToken || sessionToken.length !== 64) {
    return false;
  }
  
  try {
    const db = getDatabase();
    if (!db) return false;
    
    const sessionStmt = await db.prepare(`
      SELECT s.*, u.username 
      FROM admin_sessions s 
      JOIN admin_users u ON s.user_id = u.id 
      WHERE s.token = ? AND s.expires_at > datetime('now') AND s.is_active = 1 AND u.is_active = 1
    `);
    const session = await sessionStmt.bind(sessionToken).first();
    
    return !!session;
  } catch (error) {
    console.error('Server auth validation error:', error);
    return false;
  }
}

export default async function AdminDashboard() {
  // Server-side authentication - cannot be bypassed by intercepting client requests
  const isAuthenticated = await validateServerAuth();
  
  if (!isAuthenticated) {
    redirect('/admin/unauthorized');
  }
  
  // If we reach here, user is authenticated on server-side
  return <AdminDashboardClient />;
}
