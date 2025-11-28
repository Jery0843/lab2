import { getDatabase } from './db';

export interface NewsletterSubscriber {
  id?: number;
  name: string;
  email: string;
  country: string;
  ip_address?: string;
  created_at?: string;
}

export class NewsletterDB {
  private db: any;

  constructor(database?: any) {
    this.db = database || getDatabase();
  }

  async createTableIfNotExists() {
    if (!this.db) {
      throw new Error('Database not available');
    }
    const sql = `
      CREATE TABLE IF NOT EXISTS newsletter_subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        country TEXT NOT NULL,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;
    await this.db.query(sql);
  }

  async addSubscriber(subscriber: NewsletterSubscriber): Promise<boolean> {
    if (!this.db) {
      throw new Error('Database not available');
    }
    const sql = `
      INSERT INTO newsletter_subscribers (name, email, country, ip_address)
      VALUES (?, ?, ?, ?)
    `;
    try {
      const result = await this.db.query(sql, [subscriber.name, subscriber.email, subscriber.country, subscriber.ip_address]);
      return result.success !== false;
    } catch (error) {
      console.error('Error adding subscriber:', error);
      return false;
    }
  }

  async isEmailSubscribed(email: string): Promise<boolean> {
    if (!this.db) {
      throw new Error('Database not available');
    }
    const sql = `
      SELECT id FROM newsletter_subscribers WHERE email = ?
    `;
    const result = await this.db.query(sql, [email]);
    return result.results && result.results.length > 0;
  }

  async getAllSubscribers(): Promise<NewsletterSubscriber[]> {
    if (!this.db) {
      console.warn('Database not available for fetching subscribers');
      return [];
    }
    try {
      const prepared = await this.db.prepare('SELECT * FROM newsletter_subscribers');
      const subscribers = await prepared.all();
      return subscribers || [];
    } catch (error) {
      console.error('Error fetching subscribers:', error);
      return [];
    }
  }
}
