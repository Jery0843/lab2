import { NextRequest, NextResponse } from 'next/server';
import { NewsletterDB } from '@/lib/newsletter-db';
import { emailService } from '@/lib/email-service';
import { getUserIP } from '@/lib/utils';

export async function POST(request: NextRequest) {
  try {
    const data = await request.json();
    const { name, email, country } = data;

    if (!name || !email || !country) {
      return NextResponse.json({ success: false, error: 'Missing required fields' }, { status: 400 });
    }

    // Get user's IP address from request headers
    const ip_address = getUserIP(request);

    const newsletterDB = new NewsletterDB();
    await newsletterDB.createTableIfNotExists();

    const alreadySubscribed = await newsletterDB.isEmailSubscribed(email);
    if (alreadySubscribed) {
      return NextResponse.json({ success: false, error: 'Email already subscribed' }, { status: 409 });
    }

    const added = await newsletterDB.addSubscriber({ name, email, country, ip_address });
    if (!added) {
      return NextResponse.json({ success: false, error: 'Failed to add subscriber' }, { status: 500 });
    }

    // Send welcome email asynchronously
    emailService.sendWelcomeEmail(email, name).catch(err => {
      console.error('Failed to send welcome email:', err);
    });

    return NextResponse.json({ success: true, message: 'Successfully subscribed to newsletter' });
  } catch (error) {
    console.error('Newsletter subscription error:', error);
    return NextResponse.json({ success: false, error: 'Internal server error' }, { status: 500 });
  }
}
