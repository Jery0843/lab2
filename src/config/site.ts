/**
 * Site Configuration
 * Update these values for your deployment
 */

export const siteConfig = {
  // Domain Configuration
  domain: '0xjerry.is-a.dev',
  name: "0xJerry's Lab",
  title: "0xJerry's Lab - Cybersecurity Research & HTB Writeups",
  description: "Advanced cybersecurity research, HTB writeups, exploit development, and penetration testing guides. Learn ethical hacking techniques with detailed step-by-step tutorials.",
  
  // Author Information
  author: {
    name: "0xJerry",
    email: "dev@securenotepad.tech", // Update with your email
    twitter: "@",
    github: "https://github.com/Jery0843",
    linkedin: "https://www.linkedin.com/in/jeromeandrewk"
  },
  
  // SEO Configuration
  keywords: "cybersecurity, ethical hacking, htb writeups, hack the box, penetration testing, exploit development, red team, infosec, vulnerability research, security research",
  
  // Images
  defaultOGImage: "https://securehive.securenotepad.tech/Gemini_Generated_Image_d1jhvwd1jhvwd1jh.png",
  
  // Analytics (add your IDs here)
  analytics: {
    googleAnalytics: process.env.GOOGLE_ANALYTICS_ID,
    umami: process.env.UMAMI_WEBSITE_ID,
  },
  
  // Features
  features: {
    adminMode: true,
    search: true,
    comments: false, // Future implementation
    newsletter: false, // Future implementation
  }
};

// Helper to get the site URL dynamically
export function getSiteUrl(): string {
  // For production, prioritize custom domain
  if (process.env.NODE_ENV === 'production') {
    return process.env.NEXT_PUBLIC_SITE_URL || `https://${siteConfig.domain}`;
  }
  
  // For development
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  
  return 'http://localhost:3000';
}

export default siteConfig;
