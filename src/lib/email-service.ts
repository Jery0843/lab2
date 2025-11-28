import { NewsletterDB } from './newsletter-db';
import { getSiteUrl } from '@/config/site';
import { getDatabase } from './db';

interface EmailData {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export class EmailService {
  private apiKey: string;
  private domain: string;
  private baseUrl: string;

  constructor() {
    this.apiKey = process.env.MAILGUN_API_KEY || '';
    this.domain = process.env.MAILGUN_DOMAIN || '';
    this.baseUrl = `https://api.mailgun.net/v3/${this.domain}`;

    if (!this.apiKey || !this.domain) {
      console.warn('Mailgun credentials not configured. Email notifications will be disabled.');
    }
  }

  private async sendEmail(emailData: EmailData): Promise<boolean> {
    // Try Mailgun first
    if (this.apiKey && this.domain) {
      try {
        const formData = new FormData();
        formData.append('from', `0xJerry's Lab <noreply@${this.domain}>`);
        formData.append('to', emailData.to);
        formData.append('subject', emailData.subject);
        formData.append('html', emailData.html);
        if (emailData.text) {
          formData.append('text', emailData.text);
        }

        const basicAuth = typeof btoa === 'function'
          ? btoa(`api:${this.apiKey}`)
          : Buffer.from(`api:${this.apiKey}`).toString('base64');

        const response = await fetch(`${this.baseUrl}/messages`, {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${basicAuth}`,
          },
          body: formData,
        });

        if (response.ok) {
          const result = await response.json();
          console.log('Email sent via Mailgun:', result.id);
          return true;
        }

        const error = await response.text();
        console.error('Mailgun failed:', error);
      } catch (error) {
        console.error('Mailgun error:', error);
      }
    }

    // Fallback to Brevo
    return this.sendEmailViaBrevo(emailData);
  }

  private async sendEmailViaBrevo(emailData: EmailData): Promise<boolean> {
    const brevoApiKey = process.env.BREVO_API_KEY;
    
    if (!brevoApiKey) {
      console.warn('Brevo API key not configured');
      return false;
    }
    
    try {
      const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'api-key': brevoApiKey,
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          sender: {
            name: "0xJerry's Lab",
            email: "noreply@jerome.co.in"
          },
          to: [{
            email: emailData.to,
            name: emailData.to.split('@')[0]
          }],
          subject: emailData.subject,
          htmlContent: emailData.html
        })
      });

      if (!response.ok) {
        const error = await response.text();
        console.error('Brevo API error:', error);
        return false;
      }

      const result = await response.json();
      console.log('Email sent via Brevo:', result.messageId);
      return true;
    } catch (error) {
      console.error('Brevo error:', error);
      return false;
    }
  }

  async sendWelcomeEmail(email: string, name: string): Promise<boolean> {
    const siteUrl = getSiteUrl();
    const subject = 'Welcome to 0xJerry\'s Lab Newsletter!';
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .button { display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🎉 Welcome to 0xJerry's Lab!</h1>
            </div>
            <div class="content">
              <h2>Hello ${name}!</h2>
              <p>Thank you for subscribing to our newsletter. You're now part of an exclusive community of cybersecurity enthusiasts who stay ahead of the curve.</p>

              <p>What you can expect:</p>
              <ul>
                <li>🛡️ Latest cybersecurity insights and trends</li>
                <li>💻 Detailed HTB machine writeups</li>
                <li>🛠️ New tools and techniques</li>
                <li>🎯 Exclusive content and early access</li>
              </ul>

              <p>Stay curious, keep learning, and welcome to the community!</p>

              <a href="${siteUrl}" class="button">Visit 0xJerry's Lab</a>

              <p>If you have any questions, feel free to reply to this email.</p>
            </div>
            <div class="footer">
              <p>You're receiving this because you subscribed to our newsletter.</p>
              <p>© 2025 0xJerry's Lab | Built in the shadows, compiled with curiosity.</p>
            </div>
          </div>
        </body>
      </html>
    `;

    return this.sendEmail({ to: email, subject, html });
  }

  async sendNewMachineNotification(machineName: string, machineOs: string, machineDifficulty: string): Promise<void> {
    const newsletterDB = new NewsletterDB();
    const subscribers = await newsletterDB.getAllSubscribers();
    const members = await this.getActiveMembers();

    // Prioritize members first, then newsletter subscribers
    const memberEmails = members.map(m => ({ ...m, type: 'member' }));
    const subscriberEmails = subscribers.filter(s => !members.some(m => m.email === s.email))
      .map(s => ({ email: s.email, name: s.name, type: 'subscriber' }));
    
    const allEmails = [...memberEmails, ...subscriberEmails];

    if (allEmails.length === 0) {
      console.log('No subscribers or members to notify about new machine');
      return;
    }

    const siteUrl = getSiteUrl();
    const subject = `🚀 New ${machineDifficulty} Machine: ${machineName}`;
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .machine-card { background: white; border: 2px solid #667eea; border-radius: 10px; padding: 20px; margin: 20px 0; }
            .difficulty { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }
            .easy { background: #4CAF50; }
            .medium { background: #FF9800; }
            .hard { background: #F44336; }
            .insane { background: #9C27B0; }
            .button { display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🚀 New Machine Alert!</h1>
            </div>
            <div class="content">
              <p>A new machine has been added to our collection!</p>

              <div class="machine-card">
                <h2 style="margin-top: 0; color: #667eea;">${machineName}</h2>
                <p><strong>OS:</strong> ${machineOs}</p>
                <span class="difficulty ${machineDifficulty.toLowerCase()}">${machineDifficulty}</span>
              </div>

              <p>Ready to test your skills? Head over to our machines section and give it a try!</p>

              <a href="${siteUrl}/machines" class="button">View All Machines</a>

              <p>Happy hacking! 🛡️</p>
            </div>
            <div class="footer">
              <p>You're receiving this because you subscribed to our newsletter.</p>
              <p>© 2025 0xJerry's Lab | Built in the shadows, compiled with curiosity.</p>
            </div>
          </div>
        </body>
      </html>
    `;

    // Check if members below 300 threshold
    if (allEmails.length > 300) {
      console.log(`Too many recipients (${allEmails.length}), limiting to 300`);
    }
    
    const maxEmails = Math.min(allEmails.length, 300);
    const emailsToSend = allEmails.slice(0, maxEmails);
    const batch1Size = 80;
    
    console.log(`Sending ${emailsToSend.length}/${allEmails.length} emails in 2 batches`);
    
    let totalSuccess = 0;
    
    // Batch 1: First 80 emails
    try {
      const batch1 = emailsToSend.slice(0, batch1Size);
      const results1 = await Promise.allSettled(
        batch1.map(recipient => this.sendEmail({ to: recipient.email, subject, html }))
      );
      const successful1 = results1.filter(r => r.status === 'fulfilled' && (r as PromiseFulfilledResult<boolean>).value).length;
      totalSuccess += successful1;
      console.log(`Batch 1: ${successful1}/${batch1.length} emails sent`);
    } catch (error) {
      console.error('Batch 1 error:', error);
    }
    
    // Batch 2: Remaining emails
    try {
      const batch2 = emailsToSend.slice(batch1Size);
      const results2 = await Promise.allSettled(
        batch2.map(recipient => this.sendEmail({ to: recipient.email, subject, html }))
      );
      const successful2 = results2.filter(r => r.status === 'fulfilled' && (r as PromiseFulfilledResult<boolean>).value).length;
      totalSuccess += successful2;
      console.log(`Batch 2: ${successful2}/${batch2.length} emails sent`);
    } catch (error) {
      console.error('Batch 2 error:', error);
    }

    console.log(`Completed: ${totalSuccess}/${emailsToSend.length} emails sent, ${allEmails.length - emailsToSend.length} skipped`);
  }

  async sendWriteupAccessNotification(title: string, ctfName: string, email: string, name: string, ip: string): Promise<boolean> {
    const subject = `🔓 CTF Writeup Access: ${title}`;
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔓 CTF Writeup Access</h1>
            </div>
            <div class="content">
              <p><strong>Writeup:</strong> ${title}</p>
              <p><strong>CTF:</strong> ${ctfName}</p>
              <p><strong>Accessed by:</strong> ${name} (${email})</p>
              <p><strong>IP:</strong> ${ip}</p>
              <p><strong>Time:</strong> ${new Date().toISOString()}</p>
            </div>
            <div class="footer">
              <p>© 2025 0xJerry's Lab | Access notification</p>
            </div>
          </div>
        </body>
      </html>
    `;

    return this.sendEmail({ to: 'admin@0jerome.co.in', subject, html });
  }

  async sendNewWriteupNotification(writeupTitle: string, platform: string, category: string, difficulty: string): Promise<void> {
    const newsletterDB = new NewsletterDB();
    const subscribers = await newsletterDB.getAllSubscribers();
    const members = await this.getActiveMembers();

    // Prioritize members first, then newsletter subscribers
    const memberEmails = members.map(m => ({ ...m, type: 'member' }));
    const subscriberEmails = subscribers.filter(s => !members.some(m => m.email === s.email))
      .map(s => ({ email: s.email, name: s.name, type: 'subscriber' }));
    
    const allEmails = [...memberEmails, ...subscriberEmails];
    
    if (allEmails.length === 0) {
      console.log('No subscribers or members to notify about new writeup');
      return;
    }

    const siteUrl = getSiteUrl();
    const subject = `📝 New ${difficulty} Writeup: ${writeupTitle}`;
    
    // Dynamic URL based on platform
    let buttonUrl = `${siteUrl}/ctf`;
    let platformLabel = platform;
    
    if (platform === 'HackTheBox') {
      buttonUrl = `${siteUrl}/machines/htb`;
      platformLabel = 'HTB';
    } else if (platform === 'TryHackMe') {
      buttonUrl = `${siteUrl}/machines/thm`;
      platformLabel = 'THM';
    }
    
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .writeup-card { background: white; border: 2px solid #667eea; border-radius: 10px; padding: 20px; margin: 20px 0; }
            .difficulty { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }
            .easy { background: #4CAF50; }
            .medium { background: #FF9800; }
            .hard { background: #F44336; }
            .insane { background: #9C27B0; }
            .button { display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>📝 New Writeup Available!</h1>
            </div>
            <div class="content">
              <p>A new writeup has been published!</p>

              <div class="writeup-card">
                <h2 style="margin-top: 0; color: #667eea;">${writeupTitle}</h2>
                <p><strong>Platform:</strong> ${platformLabel}</p>
                <p><strong>Category:</strong> ${category}</p>
                <span class="difficulty ${difficulty.toLowerCase()}">${difficulty}</span>
              </div>

              <p>Ready to learn new techniques? Check out the writeup now!</p>

              <a href="${buttonUrl}" class="button">View Writeups</a>

              <p>Happy learning! 🎯</p>
            </div>
            <div class="footer">
              <p>You're receiving this because you subscribed to our newsletter.</p>
              <p>© 2025 0xJerry's Lab | Built in the shadows, compiled with curiosity.</p>
            </div>
          </div>
        </body>
      </html>
    `;

    // Check if members below 300 threshold
    if (allEmails.length > 300) {
      console.log(`Too many recipients (${allEmails.length}), limiting to 300`);
    }
    
    const maxEmails = Math.min(allEmails.length, 300);
    const emailsToSend = allEmails.slice(0, maxEmails);
    const batch1Size = 80;
    
    console.log(`Sending ${emailsToSend.length}/${allEmails.length} emails in 2 batches`);
    
    let totalSuccess = 0;
    
    // Batch 1: First 80 emails
    try {
      const batch1 = emailsToSend.slice(0, batch1Size);
      const results1 = await Promise.allSettled(
        batch1.map(recipient => this.sendEmail({ to: recipient.email, subject, html }))
      );
      const successful1 = results1.filter(r => r.status === 'fulfilled' && (r as PromiseFulfilledResult<boolean>).value).length;
      totalSuccess += successful1;
      console.log(`Batch 1: ${successful1}/${batch1.length} emails sent`);
    } catch (error) {
      console.error('Batch 1 error:', error);
    }
    
    // Batch 2: Remaining emails
    try {
      const batch2 = emailsToSend.slice(batch1Size);
      const results2 = await Promise.allSettled(
        batch2.map(recipient => this.sendEmail({ to: recipient.email, subject, html }))
      );
      const successful2 = results2.filter(r => r.status === 'fulfilled' && (r as PromiseFulfilledResult<boolean>).value).length;
      totalSuccess += successful2;
      console.log(`Batch 2: ${successful2}/${batch2.length} emails sent`);
    } catch (error) {
      console.error('Batch 2 error:', error);
    }

    console.log(`Completed: ${totalSuccess}/${emailsToSend.length} emails sent, ${allEmails.length - emailsToSend.length} skipped`);
  }

  private async getActiveMembers(): Promise<Array<{email: string, name?: string}>> {
    try {
      const db = getDatabase();
      if (!db) {
        console.warn('Database not available for fetching members');
        return [];
      }

      const prepared = await db.prepare('SELECT email, name FROM members');
      const members = await prepared.all();
      return members || [];
    } catch (error) {
      console.error('Error fetching active members:', error);
      return [];
    }
  }
}

export const emailService = new EmailService();
