'use client';

import { motion } from 'framer-motion';
import Layout from '@/components/Layout';
import { FaUserSecret, FaDatabase, FaLock, FaCookieBite } from 'react-icons/fa';

export default function PrivacyPage() {
  return (
    <Layout>
      <div className="py-8 px-4 md:px-6 lg:px-8 max-w-4xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="text-center mb-12">
            <FaUserSecret className="w-16 h-16 text-cyber-purple mx-auto mb-4" />
            <h1 className="text-4xl md:text-5xl font-cyber font-bold text-cyber-purple mb-4">
              PRIVACY POLICY
            </h1>
            <p className="text-cyber-blue text-lg">
              Data Protection Framework // 0xJerry&apos;s Lab Platform
            </p>
          </div>

          <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 md:p-8 space-y-8">
            
            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4 flex items-center gap-3">
                <FaLock className="text-cyber-green" />
                1. PRIVACY COMMITMENT
              </h2>
              <p className="text-gray-300 light:text-gray-700 leading-relaxed mb-4">
                0xJerry&apos;s Lab is committed to protecting your privacy and personal information. This Privacy Policy explains how we collect, use, store, and protect your data when you use our Platform.
              </p>
              <p className="text-gray-300 light:text-gray-700 leading-relaxed">
                We believe in transparency and will clearly communicate our data practices. By using our Platform, you consent to the data practices described in this policy.
              </p>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4 flex items-center gap-3">
                <FaDatabase className="text-cyber-purple" />
                2. INFORMATION WE COLLECT
              </h2>
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-cyber-green mb-3">2.1 Account Information</h3>
                  <ul className="list-disc list-inside ml-4 space-y-2 text-gray-300 light:text-gray-700">
                    <li>Ko-fi or Buy Me a Coffee username and profile information</li>
                    <li>Email address (through Ko-fi or Buy Me a Coffee integration)</li>
                    <li>Membership status and subscription details</li>
                    <li>Payment information (processed by Ko-fi or Buy Me a Coffee, not stored by us)</li>
                  </ul>
                </div>
                
                <div>
                  <h3 className="text-lg font-semibold text-cyber-green mb-3">2.2 Usage Data</h3>
                  <ul className="list-disc list-inside ml-4 space-y-2 text-gray-300 light:text-gray-700">
                    <li>Pages visited and content accessed</li>
                    <li>Time spent on different sections</li>
                    <li>Machine access patterns and timestamps</li>
                    <li>IP addresses and geographic location (general)</li>
                    <li>Device information and browser type</li>
                  </ul>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-cyber-green mb-3">2.3 Technical Data</h3>
                  <ul className="list-disc list-inside ml-4 space-y-2 text-gray-300 light:text-gray-700">
                    <li>Session logs and authentication records</li>
                    <li>Error logs and performance metrics</li>
                    <li>Security monitoring data</li>
                    <li>API usage statistics</li>
                  </ul>
                </div>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                3. HOW WE USE YOUR INFORMATION
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">3.1 Service Provision:</strong> To provide access to educational content and manage your membership.</p>
                <p><strong className="text-cyber-green">3.2 Security Monitoring:</strong> To detect unauthorized access, password sharing, and protect Platform integrity.</p>
                <p><strong className="text-cyber-green">3.3 Platform Improvement:</strong> To analyze usage patterns and enhance user experience.</p>
                <p><strong className="text-cyber-green">3.4 Communication:</strong> To send important updates about your membership and Platform changes.</p>
                <p><strong className="text-cyber-green">3.5 Legal Compliance:</strong> To comply with applicable laws and respond to legal requests.</p>
                <p><strong className="text-cyber-green">3.6 Fraud Prevention:</strong> To prevent abuse, unauthorized access, and maintain Platform security.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4 flex items-center gap-3">
                <FaCookieBite className="text-cyber-pink" />
                4. COOKIES & TRACKING
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">4.1 Essential Cookies:</strong> Required for Platform functionality, authentication, and security.</p>
                <p><strong className="text-cyber-green">4.2 Analytics Cookies:</strong> Used to understand user behavior and improve Platform performance.</p>
                <p><strong className="text-cyber-green">4.3 Preference Cookies:</strong> Store your settings and preferences for better user experience.</p>
                <p><strong className="text-cyber-green">4.4 Third-Party Services:</strong></p>
                <ul className="list-disc list-inside ml-4 space-y-2">
                  <li>Ko-fi and Buy Me a Coffee integration for payment processing</li>
                  <li>Cloudflare for security and performance</li>
                  <li>Vercel for hosting and analytics</li>
                </ul>
                <p><strong className="text-cyber-green">4.5 Cookie Control:</strong> You can manage cookies through your browser settings, but this may affect Platform functionality.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                5. DATA SHARING & DISCLOSURE
              </h2>
              <div className="bg-cyber-green/10 border border-cyber-green/30 rounded-lg p-4 mb-4">
                <p className="text-cyber-green font-semibold mb-2">LIMITED SHARING POLICY</p>
                <p className="text-gray-300 light:text-gray-700">
                  We do not sell, rent, or trade your personal information to third parties for marketing purposes.
                </p>
              </div>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">5.1 Service Providers:</strong> We may share data with trusted service providers who assist in Platform operations.</p>
                <p><strong className="text-cyber-green">5.2 Legal Requirements:</strong> We may disclose information when required by law or to protect our rights.</p>
                <p><strong className="text-cyber-green">5.3 Security Incidents:</strong> Information may be shared with law enforcement in case of security breaches or illegal activities.</p>
                <p><strong className="text-cyber-green">5.4 Business Transfers:</strong> In case of merger or acquisition, user data may be transferred to the new entity.</p>
                <p><strong className="text-cyber-green">5.5 Anonymized Data:</strong> We may share aggregated, anonymized usage statistics for research purposes.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                6. DATA SECURITY
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">6.1 Encryption:</strong> All data transmission is encrypted using industry-standard TLS protocols.</p>
                <p><strong className="text-cyber-green">6.2 Access Controls:</strong> Strict access controls limit who can view your personal information.</p>
                <p><strong className="text-cyber-green">6.3 Regular Audits:</strong> We conduct regular security audits and vulnerability assessments.</p>
                <p><strong className="text-cyber-green">6.4 Incident Response:</strong> We have procedures in place to respond quickly to security incidents.</p>
                <p><strong className="text-cyber-green">6.5 Data Minimization:</strong> We collect only the data necessary for Platform functionality.</p>
                <p><strong className="text-cyber-green">6.6 Secure Infrastructure:</strong> Our Platform is hosted on secure, monitored infrastructure with regular backups.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                7. DATA RETENTION
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">7.1 Active Accounts:</strong> We retain your data while your membership is active and for legitimate business purposes.</p>
                <p><strong className="text-cyber-green">7.2 Inactive Accounts:</strong> Data from inactive accounts may be retained for up to 2 years for security and legal purposes.</p>
                <p><strong className="text-cyber-green">7.3 Legal Requirements:</strong> Some data may be retained longer to comply with legal obligations.</p>
                <p><strong className="text-cyber-green">7.4 Security Logs:</strong> Security and access logs are retained for up to 1 year for monitoring and investigation purposes.</p>
                <p><strong className="text-cyber-green">7.5 Anonymized Data:</strong> Anonymized usage statistics may be retained indefinitely for research and improvement.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                8. YOUR PRIVACY RIGHTS
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">8.1 Access Rights:</strong> You can request access to your personal data we hold.</p>
                <p><strong className="text-cyber-green">8.2 Correction Rights:</strong> You can request correction of inaccurate personal information.</p>
                <p><strong className="text-cyber-green">8.3 Deletion Rights:</strong> You can request deletion of your personal data, subject to legal requirements.</p>
                <p><strong className="text-cyber-green">8.4 Portability Rights:</strong> You can request a copy of your data in a structured, machine-readable format.</p>
                <p><strong className="text-cyber-green">8.5 Objection Rights:</strong> You can object to certain types of data processing.</p>
                <p><strong className="text-cyber-green">8.6 Withdrawal of Consent:</strong> You can withdraw consent for data processing where consent is the legal basis.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                9. INTERNATIONAL DATA TRANSFERS
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">9.1 Global Infrastructure:</strong> Our Platform uses global cloud infrastructure which may involve international data transfers.</p>
                <p><strong className="text-cyber-green">9.2 Adequate Protection:</strong> We ensure adequate protection for international transfers through appropriate safeguards.</p>
                <p><strong className="text-cyber-green">9.3 Service Providers:</strong> Our service providers are contractually bound to protect your data according to applicable privacy laws.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                10. CHILDREN&apos;S PRIVACY
              </h2>
              <div className="bg-cyber-purple/10 border border-cyber-purple/30 rounded-lg p-4 mb-4">
                <p className="text-cyber-purple font-semibold mb-2">AGE RESTRICTION</p>
                <p className="text-gray-300 light:text-gray-700">
                  Our Platform is not intended for children under 18. We do not knowingly collect personal information from minors.
                </p>
              </div>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">10.1 Parental Consent:</strong> Users under 18 must have verifiable parental consent to use the Platform.</p>
                <p><strong className="text-cyber-green">10.2 Data Deletion:</strong> If we discover we have collected data from a child without consent, we will delete it immediately.</p>
                <p><strong className="text-cyber-green">10.3 Reporting:</strong> Parents can contact us to review, modify, or delete their child&apos;s information.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                11. POLICY UPDATES
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">11.1 Notification:</strong> We will notify users of significant privacy policy changes through the Platform or email.</p>
                <p><strong className="text-cyber-green">11.2 Effective Date:</strong> Changes become effective 30 days after notification unless immediate changes are required for legal compliance.</p>
                <p><strong className="text-cyber-green">11.3 Continued Use:</strong> Continued use of the Platform after changes constitutes acceptance of the updated policy.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                12. CONTACT & COMPLAINTS
              </h2>
              <div className="bg-cyber-blue/10 border border-cyber-blue/30 rounded-lg p-4">
                <p className="text-gray-300 light:text-gray-700 mb-4">
                  For privacy-related questions, data requests, or complaints, contact us through:
                </p>
                <ul className="text-cyber-blue space-y-1 mb-4">
                  <li>• Ko-fi messaging system</li>
                  <li>• Buy Me a Coffee messaging system</li>
                  <li>• Platform contact form</li>
                  <li>• Email: admin@jerome.co.in</li>
                </ul>
                <p className="text-gray-300 light:text-gray-700 text-sm">
                  We will respond to privacy requests within 30 days.
                </p>
              </div>
            </section>

            <div className="text-center pt-8 border-t border-white/10">
              <p className="text-gray-400 text-sm">
                Last Updated: November 15, 2024
              </p>
              <p className="text-cyber-purple mt-2">
                Your privacy is important to us. We are committed to protecting your personal information.
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    </Layout>
  );
}