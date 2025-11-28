# 0xJerry's Lab - Deployment Version

This is the optimized deployment version of 0xJerry's Lab with password-protected machine access and Ko-fi widget integration.

## New Features Added

### Password-Protected Machine Access
- Active machines now require password authentication
- Password form replaces "Request Access" button
- Membership notice directs users to Ko-fi widget
- Database includes password column for machines

### Ko-fi Widget Integration
- Floating chat widget for donations/support
- Positioned on right side of all pages
- Custom styling to match theme

## Quick Deploy

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your Cloudflare credentials
   ```

3. **Deploy database schema:**
   ```bash
   npx wrangler d1 execute lab-database --file=./database/schema.sql
   ```

4. **Deploy to Vercel:**
   ```bash
   npm run build
   vercel --prod
   ```

## Test Password Feature

- Machine: Academy (id: academy)
- Password: academy123

## File Structure

```
src/
├── app/
│   ├── api/verify-password/     # Password verification endpoint
│   └── layout.tsx               # Ko-fi widget integration
├── components/
│   └── ActiveMachine403.tsx     # Updated with password form
└── lib/db.ts                    # Updated with password field
```

## Environment Variables

```bash
CLOUDFLARE_API_TOKEN=your_token
CLOUDFLARE_ACCOUNT_ID=your_account_id
CLOUDFLARE_DATABASE_ID=your_database_id
```

Ready for deployment! 🚀