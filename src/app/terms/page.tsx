'use client';

import { motion } from 'framer-motion';
import Layout from '@/components/Layout';
import { FaShieldAlt, FaExclamationTriangle, FaUserShield } from 'react-icons/fa';

export default function TermsPage() {
  return (
    <Layout>
      <div className="py-8 px-4 md:px-6 lg:px-8 max-w-4xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="text-center mb-12">
            <FaShieldAlt className="w-16 h-16 text-cyber-green mx-auto mb-4" />
            <h1 className="text-4xl md:text-5xl font-cyber font-bold text-cyber-green mb-4">
              TERMS & CONDITIONS
            </h1>
            <p className="text-cyber-blue text-lg">
              Legal Framework // 0xJerry&apos;s Lab Platform
            </p>
          </div>

          <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 md:p-8 space-y-8">
            
            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4 flex items-center gap-3">
                <FaUserShield className="text-cyber-green" />
                1. ACCEPTANCE OF TERMS
              </h2>
              <p className="text-gray-300 light:text-gray-700 leading-relaxed mb-4">
                By accessing and using 0xJerry&apos;s Lab (&quot;the Platform&quot;), you acknowledge that you have read, understood, and agree to be bound by these Terms and Conditions. If you do not agree to these terms, you must not use the Platform.
              </p>
              <p className="text-gray-300 light:text-gray-700 leading-relaxed">
                These terms constitute a legally binding agreement between you and 0xJerry&apos;s Lab. We reserve the right to modify these terms at any time without prior notice.
              </p>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                2. MEMBERSHIP & ACCESS
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">2.1 Membership Requirements:</strong> Access to premium content requires active membership through Ko-fi or Buy Me a Coffee subscription.</p>
                <p><strong className="text-cyber-green">2.2 Account Security:</strong> You are responsible for maintaining the confidentiality of your account credentials and passwords.</p>
                <p><strong className="text-cyber-green">2.3 Personal Use Only:</strong> Membership is for individual, non-commercial use only. Sharing access credentials is strictly prohibited.</p>
                <p><strong className="text-cyber-green">2.4 Age Requirement:</strong> Users must be at least 18 years old or have parental consent to use the Platform.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4 flex items-center gap-3">
                <FaExclamationTriangle className="text-cyber-pink" />
                3. PASSWORD SHARING POLICY
              </h2>
              <div className="bg-cyber-pink/10 border border-cyber-pink/30 rounded-lg p-4 mb-4">
                <p className="text-cyber-pink font-semibold mb-2">STRICT PROHIBITION</p>
                <p className="text-gray-300 light:text-gray-700">
                  Sharing machine access passwords with unauthorized individuals is strictly forbidden and will result in immediate account termination.
                </p>
              </div>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">3.1 Zero Tolerance:</strong> Any evidence of password sharing will result in immediate membership cancellation without warning.</p>
                <p><strong className="text-cyber-green">3.2 Monitoring:</strong> We actively monitor access patterns and may investigate suspicious activities.</p>
                <p><strong className="text-cyber-green">3.3 Consequences:</strong> Violators will be permanently banned from the Platform with no possibility of reinstatement.</p>
                <p><strong className="text-cyber-green">3.4 Legal Action:</strong> We reserve the right to pursue legal action for unauthorized access or distribution of protected content.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                4. CONTENT & INTELLECTUAL PROPERTY
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">4.1 Proprietary Content:</strong> All writeups, tutorials, machine configurations, and educational materials are proprietary to 0xJerry&apos;s Lab.</p>
                <p><strong className="text-cyber-green">4.2 Usage Rights:</strong> Members receive limited, non-transferable rights to access content for personal educational purposes only.</p>
                <p><strong className="text-cyber-green">4.3 Prohibited Actions:</strong> You may not copy, distribute, modify, reverse engineer, or create derivative works from our content.</p>
                <p><strong className="text-cyber-green">4.4 DMCA Compliance:</strong> We respect intellectual property rights and will respond to valid DMCA takedown notices.</p>
                <p><strong className="text-cyber-green">4.5 User Submissions:</strong> Any content you submit becomes our property and may be used for Platform improvement.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                5. MEMBERSHIP CANCELLATION
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">5.1 Voluntary Cancellation:</strong> You may cancel your membership at any time through your Ko-fi or Buy Me a Coffee account settings.</p>
                <p><strong className="text-cyber-green">5.2 Immediate Termination:</strong> We reserve the right to terminate memberships immediately for violations of these terms.</p>
                <p><strong className="text-cyber-green">5.3 Grounds for Termination:</strong></p>
                <ul className="list-disc list-inside ml-4 space-y-2">
                  <li>Password sharing or unauthorized access distribution</li>
                  <li>Attempting to circumvent security measures</li>
                  <li>Harassment of other users or staff</li>
                  <li>Commercial use of educational content</li>
                  <li>Violation of applicable laws or regulations</li>
                </ul>
                <p><strong className="text-cyber-green">5.4 Post-Termination:</strong> Upon cancellation, access to premium content is immediately revoked.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                6. PAYMENT & REFUND POLICY
              </h2>
              <div className="bg-cyber-purple/10 border border-cyber-purple/30 rounded-lg p-4 mb-4">
                <p className="text-cyber-purple font-semibold mb-2">NO REFUND POLICY</p>
                <p className="text-gray-300 light:text-gray-700">
                  All payments are final and non-refundable under any circumstances.
                </p>
              </div>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">6.1 Payment Processing:</strong> All payments are processed through Ko-fi or Buy Me a Coffee secure payment systems.</p>
                <p><strong className="text-cyber-green">6.2 No Refunds:</strong> We do not provide refunds for any reason, including but not limited to:</p>
                <ul className="list-disc list-inside ml-4 space-y-2">
                  <li>Voluntary membership cancellation</li>
                  <li>Account termination due to policy violations</li>
                  <li>Technical difficulties or service interruptions</li>
                  <li>Dissatisfaction with content or services</li>
                  <li>Inability to access content due to technical limitations</li>
                </ul>
                <p><strong className="text-cyber-green">6.3 Billing Disputes:</strong> Payment disputes must be resolved through the respective platform&apos;s (Ko-fi or Buy Me a Coffee) dispute resolution process.</p>
                <p><strong className="text-cyber-green">6.4 Price Changes:</strong> We reserve the right to modify subscription prices with 30 days notice to existing members.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                7. PLATFORM USAGE & CONDUCT
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">7.1 Acceptable Use:</strong> The Platform is intended for legitimate cybersecurity education and skill development.</p>
                <p><strong className="text-cyber-green">7.2 Prohibited Activities:</strong></p>
                <ul className="list-disc list-inside ml-4 space-y-2">
                  <li>Using knowledge gained for illegal or malicious purposes</li>
                  <li>Attempting to hack or compromise the Platform infrastructure</li>
                  <li>Sharing or distributing copyrighted materials</li>
                  <li>Creating multiple accounts to circumvent restrictions</li>
                  <li>Automated scraping or data extraction</li>
                </ul>
                <p><strong className="text-cyber-green">7.3 Educational Purpose:</strong> All content is provided for educational purposes only. Users are responsible for complying with applicable laws.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                8. DISCLAIMERS & LIABILITY
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">8.1 Service Availability:</strong> We strive for 99% uptime but do not guarantee uninterrupted service availability.</p>
                <p><strong className="text-cyber-green">8.2 Content Accuracy:</strong> While we maintain high standards, we do not warrant the accuracy or completeness of all content.</p>
                <p><strong className="text-cyber-green">8.3 Limitation of Liability:</strong> Our liability is limited to the amount paid for membership in the preceding 2 months.</p>
                <p><strong className="text-cyber-green">8.4 Indemnification:</strong> Users agree to indemnify 0xJerry&apos;s Lab against claims arising from their use of the Platform.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                9. GOVERNING LAW & DISPUTES
              </h2>
              <div className="space-y-4 text-gray-300 light:text-gray-700">
                <p><strong className="text-cyber-green">9.1 Jurisdiction:</strong> These terms are governed by the laws of India.</p>
                <p><strong className="text-cyber-green">9.2 Dispute Resolution:</strong> Disputes will be resolved through binding arbitration before litigation.</p>
                <p><strong className="text-cyber-green">9.3 Severability:</strong> If any provision is deemed invalid, the remaining terms remain in full effect.</p>
              </div>
            </section>

            <section>
              <h2 className="text-2xl font-cyber font-bold text-cyber-blue mb-4">
                10. CONTACT INFORMATION
              </h2>
              <div className="bg-cyber-green/10 border border-cyber-green/30 rounded-lg p-4">
                <p className="text-gray-300 light:text-gray-700 mb-2">
                  For questions regarding these terms, contact us through:
                </p>
                <ul className="text-cyber-green space-y-1">
                  <li>• Ko-fi messaging system</li>
                  <li>• Buy Me a Coffee messaging system</li>
                  <li>• Platform contact form</li>
                  <li>• Official social media channels</li>
                </ul>
              </div>
            </section>

            <div className="text-center pt-8 border-t border-white/10">
              <p className="text-gray-400 text-sm">
                Last Updated: November 15, 2024
              </p>
              <p className="text-cyber-blue mt-2">
                By using 0xJerry&apos;s Lab, you acknowledge acceptance of these terms.
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    </Layout>
  );
}