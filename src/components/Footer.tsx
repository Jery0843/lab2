import { FaLinkedin, FaEnvelope, FaCode, FaRss } from 'react-icons/fa';

interface FooterProps {
  onOpenNewsletter: () => void;
}

const Footer = ({ onOpenNewsletter }: FooterProps) => {
  return (
  <footer className="backdrop-blur-sm bg-black/20 light:bg-white/30 border-t border-white/10 py-4 mt-auto">
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row items-center justify-between">
          {/* Copyright */}
          <div className="text-center md:text-left mb-3 md:mb-0">
            <p className="text-sm">
              © 2025 0xJerry | Built in the shadows, compiled with curiosity.
            </p>
          </div>

          {/* Social Links */}
          <div className="flex items-center space-x-6">
            <a
              href="https://www.linkedin.com/in/jeromeandrewk/"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-2 text-cyber-green hover:text-cyber-blue transition-colors duration-300 group"
            >
              <FaLinkedin className="group-hover:animate-pulse" />
              <span className="text-sm">LinkedIn</span>
            </a>
            <a
              href="mailto:OxJerry@proton.me"
              className="flex items-center space-x-2 text-cyber-green hover:text-cyber-blue transition-colors duration-300 group"
            >
              <FaEnvelope className="group-hover:animate-pulse" />
              <span className="text-sm">Email</span>
            </a>
            <button
              onClick={onOpenNewsletter}
              className="flex items-center space-x-2 text-cyber-green hover:text-cyber-blue transition-colors duration-300 group"
            >
              <FaRss className="group-hover:animate-pulse" />
              <span className="text-sm">Newsletter</span>
            </button>
            <div className="flex items-center space-x-2 text-cyber-green/60">
              <FaCode />
              <span className="text-xs">v2.0.0</span>
            </div>
          </div>
        </div>

        {/* Terminal-style status bar */}
        <div className="mt-3 pt-3 border-t border-cyber-green/20">
          <div className="flex items-center justify-between text-xs text-cyber-green/60">
            <span>[STATUS: ONLINE]</span>
            <span>[UPTIME: {new Date().getFullYear() - 2024} years]</span>
            <span>[MODE: STEALTH]</span>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
