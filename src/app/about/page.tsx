'use client';

import Layout from '@/components/Layout';
import { FaUserSecret, FaCode, FaShieldAlt } from 'react-icons/fa';

const About = () => {
  return (
    <Layout>
      <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-6 lg:p-8">
        <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold mb-6 lg:mb-8 text-center !text-gray-900 dark:!text-white">
          About
        </h1>

        {/* Main Content */}
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-8">
            {/* Left Section: Avatar & Vitals */}
            <div className="lg:col-span-1 flex flex-col items-center">
              <div className="relative w-32 h-32 sm:w-40 sm:h-40 lg:w-48 lg:h-48 rounded-full border-2 border-green-600 dark:border-cyber-green mb-4 sm:mb-6 overflow-visible group animate-pulse hover:animate-none transition-all duration-300">
                {/* Animated border ring */}
                <div className="absolute -inset-1 bg-gradient-to-r from-green-600 via-blue-600 to-green-600 dark:from-cyber-green dark:via-cyber-blue dark:to-cyber-green rounded-full opacity-75 blur-sm animate-spin group-hover:animate-pulse"></div>
                
                {/* Glitch overlay */}
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-green-600/20 dark:via-cyber-green/20 to-transparent animate-pulse rounded-full"></div>
                
                {/* Image container */}
                <div className="relative w-full h-full rounded-full border-2 border-green-600 dark:border-cyber-green bg-black overflow-hidden transform transition-all duration-300 group-hover:scale-105 group-hover:rotate-1 z-[2]">
                  <img 
                    src="https://files.jerome.co.in/0xjerry.jpeg" 
                    alt="0xJerry Profile" 
                    className="w-full h-full object-cover transition-all duration-300 group-hover:brightness-110 group-hover:contrast-110"
                    onError={(e) => {
                      // Fallback to icon if image fails to load
                      e.currentTarget.style.display = 'none';
                      e.currentTarget.nextElementSibling?.classList.remove('hidden');
                    }}
                  />
                  <FaUserSecret className="w-full h-full p-4 sm:p-6 text-green-600 dark:text-cyber-green hidden" />
                  {/* Scanning line effect */}
                  <div className="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-transparent via-green-600 dark:via-cyber-green to-transparent animate-bounce opacity-70"></div>
                </div>

                {/* Smoke overlay outside circle to allow escape */}
                <div className="smoke-container z-[3]">
                  <span className="smoke-puff drift-left"></span>
                  <span className="smoke-puff p2 drift-right"></span>
                  <span className="smoke-puff p3 drift-left"></span>
                </div>
                
                {/* Corner indicators */}
                <div className="absolute -top-1 -right-1 w-2 h-2 sm:w-3 sm:h-3 bg-green-600 dark:bg-cyber-green rounded-full animate-ping"></div>
                <div className="absolute -bottom-1 -left-1 w-1.5 h-1.5 sm:w-2 sm:h-2 bg-blue-600 dark:bg-cyber-blue rounded-full animate-pulse"></div>
              </div>
              <div className="text-center mb-4 sm:mb-6">
                <h2 className="text-xl sm:text-2xl font-cyber font-bold !text-gray-900 dark:!text-white">0xJerry</h2>
                <p className="!text-blue-600 dark:!text-cyber-blue text-sm sm:text-base font-medium">[ Redacted ]</p>
              </div>
              <div className="text-left space-y-2 sm:space-y-3 w-full max-w-xs lg:max-w-none">
                <p className="text-sm sm:text-base !text-gray-900 dark:!text-white"><strong className="!text-green-600 dark:!text-cyber-green">STATUS:</strong> <span className="!text-green-400">Online</span></p>
                <p className="text-sm sm:text-base !text-gray-900 dark:!text-white"><strong className="!text-green-600 dark:!text-cyber-green">FOCUS:</strong> <span className="!text-gray-900 dark:!text-white">Offensive Security</span></p>
                <p className="text-sm sm:text-base !text-gray-900 dark:!text-white"><strong className="!text-green-600 dark:!text-cyber-green">LOCATION:</strong> <span className="!text-gray-900 dark:!text-white">The Grid</span></p>
              </div>
            </div>

            {/* Right Section: Bio & Philosophy */}
            <div className="lg:col-span-2 rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-4 sm:p-6 lg:p-8">
              <h3 className="text-xl sm:text-2xl font-bold mb-3 sm:mb-4 text-gray-800 dark:text-gray-100">Digital Ghost in the Machine</h3>
              <p className="mb-4 sm:mb-6 text-gray-800 dark:text-gray-300 leading-relaxed text-sm sm:text-base">
                &ldquo;Chasing root one box at a time — crafting exploits, decoding patterns, and breathing life into logic. This is the digital dojo where exploits evolve into mastery.&rdquo;
              </p>

              <div className="border-t border-gray-300 dark:border-cyber-green/30 pt-4 sm:pt-6">
                <h4 className="text-lg sm:text-xl font-semibold mb-3 sm:mb-4 text-gray-800 dark:text-gray-100">Core Philosophy</h4>
                <div className="space-y-3 sm:space-y-4">
                  <div className="flex items-start space-x-3 sm:space-x-4">
                    <FaCode className="text-xl sm:text-2xl mt-1 text-green-600 dark:text-cyber-green flex-shrink-0" />
                    <div>
                      <h5 className="font-bold text-sm sm:text-base text-gray-800 dark:text-gray-100">Code is Poetry</h5>
                      <p className="text-xs sm:text-sm text-gray-800 dark:text-gray-400 leading-relaxed">Every script, payload, and exploit is a stanza in a larger narrative of digital interaction. I strive for elegance and efficiency in every line.</p>
                    </div>
                  </div>
                  <div className="flex items-start space-x-3 sm:space-x-4">
                    <FaShieldAlt className="text-xl sm:text-2xl mt-1 text-green-600 dark:text-cyber-green flex-shrink-0" />
                    <div>
                      <h5 className="font-bold text-sm sm:text-base text-gray-800 dark:text-gray-100">Defense Through Offense</h5>
                      <p className="text-xs sm:text-sm text-gray-800 dark:text-gray-400 leading-relaxed">To build resilient systems, one must first master the art of breaking them. My work is a continuous cycle of exploitation and fortification.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Skills Section */}
          <div className="mt-12 sm:mt-14 lg:mt-16">
            <h3 className="text-2xl sm:text-3xl font-cyber font-bold text-center mb-6 sm:mb-8 !text-gray-900 dark:!text-white">Technical Arsenal</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 sm:gap-4 lg:gap-6 text-center">
              {['Python', 'Bash', 'PowerShell', 'React', 'Reverse Engineering', 'Web Exploitation', 'Active Directory', 'Metasploit'].map(skill => (
                <div key={skill} className="rounded-xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-3 sm:p-4 hover:border-cyber-blue transition-all duration-300 hover:transform hover:scale-105">
                  <p className="font-semibold text-xs sm:text-sm lg:text-base break-words text-gray-800 dark:text-gray-100">{skill}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default About;
