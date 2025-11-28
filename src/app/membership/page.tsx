'use client';

import Layout from '@/components/Layout';
import { FaLock, FaKey, FaHeart } from 'react-icons/fa';
import SubscriberSpotlight from '@/components/SubscriberSpotlight';

const Membership = () => {
  return (
    <Layout>
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 max-w-7xl mx-auto px-4 sm:px-6">
        {/* Left Sidebar - Elite Members */}
        <div className="lg:col-span-1 order-2 lg:order-1">
          <SubscriberSpotlight 
            type="tiers" 
            title="Elite Members" 
            className="sticky top-20"
          />
        </div>
        
        {/* Main Content */}
        <div className="lg:col-span-3 order-1 lg:order-2">
          <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 lg:p-8">
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold mb-6 lg:mb-8 text-center !text-gray-900 dark:!text-white">
              Membership Access
            </h1>
          {/* Introduction */}
          <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 mb-8">
            <div className="flex items-center justify-center mb-4">
              <FaLock className="text-3xl text-green-600 dark:text-cyber-green mr-3" />
              <h2 className="text-xl sm:text-2xl font-bold text-gray-800 dark:text-gray-100">
                Password-Protected Content
              </h2>
            </div>
            <p className="text-gray-800 dark:text-gray-300 leading-relaxed text-center">
              Hi everyone,
            </p>
            <br />
            <p className="text-gray-800 dark:text-gray-300 leading-relaxed">
              To comply with security guidelines, all active machine writeups on my platform are now password-protected. Each machine has its own unique password to keep the content secure and exclusive for members. This protects the learning integrity of HackTheBox and ensures your access remains safe.
            </p>
            <br />
            <p className="text-gray-800 dark:text-gray-300 leading-relaxed text-center font-semibold">
              <span className="text-green-600 dark:text-cyber-green">Membership</span>, will give you full access to all passwords and exclusive writeups. Please avoid alias emails when subscribing.
            </p>
          </div>

          {/* How to Access Section */}
          <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 mb-8">
            <h3 className="text-xl sm:text-2xl font-bold mb-6 text-gray-800 dark:text-gray-100 text-center">
              How to Access Your Writeups
            </h3>

            {/* Step 1 */}
            <div className="mb-6">
              <div className="flex items-center mb-3">
                <div className="w-8 h-8 bg-green-600 dark:bg-cyber-green text-white rounded-full flex items-center justify-center font-bold mr-3">
                  1
                </div>
                <h4 className="text-lg font-semibold text-gray-800 dark:text-gray-100">Join the Membership</h4>
              </div>
              <p className="text-gray-800 dark:text-gray-300 mb-4 ml-11">
                You can subscribe using either of these platforms:
              </p>
              <div className="ml-11 space-y-3">
                <div className="flex items-center">
                  <span className="text-green-600 dark:text-cyber-blue mr-2">🔹</span>
                  <span className="text-gray-800 dark:text-gray-300">Ko-fi Membership: </span>
                  <a 
                    href="https://ko-fi.com/andres__" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-green-600 dark:text-cyber-green hover:text-blue-600 dark:hover:text-cyber-blue transition-colors ml-1 underline"
                  >
                    https://ko-fi.com/andres__
                  </a>
                </div>
                <div className="flex items-center">
                  <span className="text-green-600 dark:text-cyber-blue mr-2">🔹</span>
                  <span className="text-gray-800 dark:text-gray-300">BuyMeACoffee Membership: </span>
                  <a 
                    href="https://buymeacoffee.com/0xjerry/membership" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-green-600 dark:text-cyber-green hover:text-blue-600 dark:hover:text-cyber-blue transition-colors ml-1 underline"
                  >
                    https://buymeacoffee.com/0xjerry/membership
                  </a>
                </div>
              </div>
              <p className="text-gray-800 dark:text-gray-400 text-sm mt-3 ml-11 italic">
                If you face any issues while subscribing or don&apos;t have PayPal, feel free to use the BuyMeACoffee membership link.
              </p>
            </div>

            {/* Step 2 */}
            <div className="mb-6">
              <div className="flex items-center mb-3">
                <div className="w-8 h-8 bg-green-600 dark:bg-cyber-green text-white rounded-full flex items-center justify-center font-bold mr-3">
                  2
                </div>
                <h4 className="text-lg font-semibold text-gray-800 dark:text-gray-100">Get Your Passwords</h4>
              </div>
              <p className="text-gray-800 dark:text-gray-300 ml-11">
                Log in to the platform you subscribed on and open the <strong>Posts section</strong> — passwords for each machine will be available there.
              </p>
            </div>

            {/* Step 3 */}
            <div className="mb-6">
              <div className="flex items-center mb-3">
                <div className="w-8 h-8 bg-green-600 dark:bg-cyber-green text-white rounded-full flex items-center justify-center font-bold mr-3">
                  3
                </div>
                <h4 className="text-lg font-semibold text-gray-800 dark:text-gray-100">Unlock Full Writeups</h4>
              </div>
              <div className="ml-11">
                <p className="text-gray-800 dark:text-gray-300 mb-2">Visit:</p>
                <a 
                  href="https://0xjerry.jerome.co.in/machines/htb/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-green-600 dark:text-cyber-green hover:text-blue-600 dark:hover:text-cyber-blue transition-colors underline block mb-3"
                >
                  https://0xjerry.jerome.co.in/machines/htb/
                </a>
                <p className="text-gray-800 dark:text-gray-300">
                  Choose your machine and use the password from your membership posts to unlock the full writeup.
                </p>
              </div>
            </div>
          </div>

          {/* No Pressure Section */}
          <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 text-center">
            <div className="flex items-center justify-center mb-4">
              <FaHeart className="text-2xl text-red-500 mr-3" />
              <h3 className="text-xl font-bold text-gray-800 dark:text-gray-100">No Pressure</h3>
            </div>
            <p className="text-gray-800 dark:text-gray-300 leading-relaxed mb-4">
              Membership is completely optional — no worries if it&apos;s not for you. Thank you for the support and understanding. ❤️
            </p>
            <p className="text-gray-800 dark:text-gray-300 font-semibold">
              Best regards,<br />
              <span className="text-green-600 dark:text-cyber-green">0xJerry</span>
            </p>
          </div>

          {/* Quick Access Buttons */}
          <div className="mt-8 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <a
              href="https://ko-fi.com/andres__"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center px-6 py-3 bg-green-600 dark:bg-cyber-green text-white rounded-lg hover:bg-green-700 dark:hover:bg-cyber-blue transition-all duration-300 hover:transform hover:scale-105"
            >
              <FaKey className="mr-2" />
              Ko-fi Membership
            </a>
            <a
              href="https://buymeacoffee.com/0xjerry/membership"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center px-6 py-3 bg-blue-600 dark:bg-cyber-purple text-white rounded-lg hover:bg-blue-700 dark:hover:bg-cyber-blue transition-all duration-300 hover:transform hover:scale-105"
            >
              <FaKey className="mr-2" />
              BuyMeACoffee Membership
            </a>
          </div>

          {/* Legal Links */}
          <div className="mt-8 text-center">
            <p className="text-gray-600 dark:text-gray-400 text-sm mb-3">
              By subscribing, you agree to our:
            </p>
            <div className="flex justify-center space-x-6">
              <a
                href="/terms"
                className="text-green-600 dark:text-cyber-green hover:text-blue-600 dark:hover:text-cyber-blue transition-colors underline text-sm"
              >
                Terms & Conditions
              </a>
              <a
                href="/privacy"
                className="text-green-600 dark:text-cyber-green hover:text-blue-600 dark:hover:text-cyber-blue transition-colors underline text-sm"
              >
                Privacy Policy
              </a>
            </div>
          </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default Membership;
