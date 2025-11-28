'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { FaTerminal, FaSearch, FaCog, FaUser, FaLock, FaBars, FaTimes } from 'react-icons/fa';
import { ThemeToggle } from './ThemeToggle';
import SearchModal from './SearchModal';

interface AdminUser {
  id: number;
  username: string;
  last_login?: string;
}

const Header = () => {
  const [isAdminMode, setIsAdminMode] = useState(false);
  const [showAdminModal, setShowAdminModal] = useState(false);
  const [showSetupModal, setShowSetupModal] = useState(false);
  const [adminUser, setAdminUser] = useState<AdminUser | null>(null);
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [setupForm, setSetupForm] = useState({ username: '', password: '', confirmPassword: '', setupKey: '' });
  const [showSearchModal, setShowSearchModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showMobileMenu, setShowMobileMenu] = useState(false);
  const [hasAdminUser, setHasAdminUser] = useState(true);

  // Check admin session on component mount
  useEffect(() => {
    checkAdminSession();
    checkAdminUserExists();
  }, []);

  const checkAdminSession = async () => {
    try {
      const response = await fetch('/api/admin/auth', {
        credentials: 'include',
        cache: 'no-store'
      });
      const data = await response.json();
      
      if (data.authenticated) {
        setIsAdminMode(true);
        setAdminUser(data.user || null);
      } else {
        setIsAdminMode(false);
        setAdminUser(null);
        // Clear any stale session cookie
        document.cookie = 'admin_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      }
    } catch (error) {
      console.error('Error checking admin session:', error);
      setIsAdminMode(false);
      setAdminUser(null);
      // Clear any stale session cookie
      document.cookie = 'admin_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    }
  };

  const checkAdminUserExists = async () => {
    try {
      const response = await fetch('/api/admin/setup');
      const data = await response.json();
      setHasAdminUser(data.hasAdminUser);
    } catch (error) {
      console.error('Error checking admin user existence:', error);
    }
  };

  const handleAdminToggle = () => {
    if (isAdminMode) {
      handleLogout();
    } else {
      if (!hasAdminUser) {
        setShowSetupModal(true);
      } else {
        setShowAdminModal(true);
      }
    }
  };

  const handleAdminLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      const response = await fetch('/api/admin/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(loginForm)
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setIsAdminMode(true);
        setAdminUser(data.user);
        setShowAdminModal(false);
        setLoginForm({ username: '', password: '' });
        // Dispatch custom event to notify other components
        window.dispatchEvent(new Event('adminModeChanged'));
        // Redirect to admin dashboard if specified
        if (data.redirect) {
          window.location.href = data.redirect;
        }
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleAdminSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    if (setupForm.password !== setupForm.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }
    
    try {
      const response = await fetch('/api/admin/setup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: setupForm.username,
          password: setupForm.password,
          setupKey: setupForm.setupKey
        })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setHasAdminUser(true);
        setShowSetupModal(false);
        setSetupForm({ username: '', password: '', confirmPassword: '', setupKey: '' });
        // Auto login with the created user
        setLoginForm({ username: setupForm.username, password: setupForm.password });
        setTimeout(() => {
          setShowAdminModal(true);
        }, 500);
      } else {
        setError(data.error || 'Setup failed');
      }
    } catch (error) {
      console.error('Setup error:', error);
      setError('Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/admin/auth', { 
        method: 'DELETE',
        credentials: 'include'
      });
      setIsAdminMode(false);
      setAdminUser(null);
      // Clear session cookie
      document.cookie = 'admin_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      // Dispatch custom event to notify other components
      window.dispatchEvent(new Event('adminModeChanged'));
      // Redirect to home if currently on admin page
      if (window.location.pathname.startsWith('/admin')) {
        window.location.href = '/';
      }
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  return (
    <>
      <header className="glass-panel backdrop-blur-sm sticky top-0 z-[100]">
        <div className="container mx-auto px-4 py-3 sm:py-4">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <Link href="/" className="flex items-center space-x-2 group">
              <FaTerminal className="text-cyber-green text-xl sm:text-2xl group-hover:animate-pulse" />
              <span className="text-base sm:text-xl font-cyber font-bold" data-text="0xJerry&apos;s Lab">
                0xJerry&apos;s Lab
              </span>
            </Link>

            {/* Desktop Navigation */}
            <nav className="hidden lg:flex items-center space-x-6">
              <Link 
                href="/" 
                className="hover:text-cyber-blue transition-colors duration-300 hover:glow text-sm xl:text-base"
              >
                ~/home
              </Link>
              <Link 
                href="/machines" 
                className="hover:text-cyber-blue transition-colors duration-300 text-sm xl:text-base"
              >
                ./writeups
              </Link>
              <Link 
                href="/membership" 
                className="hover:text-cyber-blue transition-colors duration-300 text-sm xl:text-base"
              >
                ./membership
              </Link>
              <Link 
                href="/news" 
                className="hover:text-cyber-blue transition-colors duration-300 text-sm xl:text-base"
              >
                ./news
              </Link>
              <Link 
                href="/forums" 
                className="hover:text-cyber-blue transition-colors duration-300 text-sm xl:text-base"
              >
                ./forums
              </Link>
              <Link 
                href="/tools" 
                className="hover:text-cyber-blue transition-colors duration-300 text-sm xl:text-base"
              >
                ./tools
              </Link>

              <Link 
                href="/about" 
                className="hover:text-cyber-blue transition-colors duration-300 text-sm xl:text-base"
              >
                ./about
              </Link>
              <Link 
                href="https://jerome.is-a.dev/contact" 
                className="hover:text-cyber-blue transition-colors duration-300 text-sm xl:text-base"
                target="_blank"
                rel="noopener noreferrer"
              >
                ./contact
              </Link>
            </nav>

            {/* Desktop Theme, Admin & Search */}
            <div className="hidden sm:flex items-center space-x-3 lg:space-x-4">
              <button 
                className="text-cyber-green hover:text-cyber-blue transition-colors p-2"
                title="Search"
                onClick={() => setShowSearchModal(true)}
              >
                <FaSearch className="text-sm lg:text-base" />
              </button>
              <ThemeToggle />
              <div className="relative">
                <button 
                  onClick={handleAdminToggle}
                  className={`p-2 rounded-full transition-all duration-300 ${
                    isAdminMode 
                      ? 'bg-cyber-pink/20 text-cyber-pink hover:text-red-400' 
                      : 'text-cyber-green hover:text-cyber-blue hover:bg-cyber-green/20'
                  }`}
                  title={isAdminMode ? 'Exit Admin Mode' : 'Enter Admin Mode'}
                >
                  <FaCog className={`text-sm lg:text-base ${isAdminMode ? 'animate-spin' : ''}`} />
                </button>
                {isAdminMode && (
                  <div className="absolute -bottom-1 -right-1 w-2 h-2 lg:w-3 lg:h-3 bg-cyber-pink rounded-full animate-pulse" />
                )}
              </div>
            </div>

            {/* Mobile Menu Button & Controls */}
            <div className="flex items-center space-x-2 sm:hidden">
              <button 
                className="text-cyber-green hover:text-cyber-blue transition-colors p-2"
                title="Search"
                onClick={() => setShowSearchModal(true)}
              >
                <FaSearch className="text-sm" />
              </button>
              <ThemeToggle />
              <button
                onClick={() => setShowMobileMenu(!showMobileMenu)}
                className="text-cyber-green hover:text-cyber-blue transition-colors p-2"
                title="Menu"
              >
                {showMobileMenu ? <FaTimes /> : <FaBars />}
              </button>
            </div>
          </div>

          {/* Mobile Navigation Menu */}
          {showMobileMenu && (
            <div className="lg:hidden mt-4 pb-4 border-t border-cyber-green/30 pt-4">
              <nav className="flex flex-col space-y-3">
                <Link 
                  href="/" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                >
                  ~/home
                </Link>
                <Link 
                  href="/machines" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                >
                  ./writeups
                </Link>
                <Link 
                  href="/membership" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                >
                  ./membership
                </Link>
                <Link 
                  href="/news" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                >
                  ./news
                </Link>
                <Link 
                  href="/forums" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                >
                  ./forums
                </Link>
                <Link 
                  href="/tools" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                >
                  ./tools
                </Link>

                <Link 
                  href="/about" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                >
                  ./about
                </Link>
                <Link 
                  href="https://jerome.is-a.dev/contact" 
                  className="text-sm hover:text-cyber-blue transition-colors py-2"
                  onClick={() => setShowMobileMenu(false)}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  ./contact
                </Link>
                
                {/* Mobile Admin Button */}
                <div className="pt-3 border-t border-cyber-green/30 mt-3">
                  <button 
                    onClick={() => {
                      handleAdminToggle();
                      setShowMobileMenu(false);
                    }}
                    className={`flex items-center space-x-2 text-sm transition-all duration-300 py-2 ${
                      isAdminMode 
                        ? 'text-cyber-pink' 
                        : 'text-cyber-green hover:text-cyber-blue'
                    }`}
                  >
                    <FaCog className={isAdminMode ? 'animate-spin' : ''} />
                    <span>{isAdminMode ? 'Exit Admin Mode' : 'Enter Admin Mode'}</span>
                    {isAdminMode && (
                      <div className="w-2 h-2 bg-cyber-pink rounded-full animate-pulse" />
                    )}
                  </button>
                </div>
              </nav>
            </div>
          )}

          {/* Tablet Navigation - visible on md screens only */}
          <nav className="hidden sm:flex lg:hidden mt-4 flex-wrap gap-3 sm:gap-4 border-t border-cyber-green/30 pt-3">
            <Link href="/" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors">~/home</Link>
            <Link href="/machines" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors">./writeups</Link>
            <Link href="/membership" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors">./membership</Link>
            <Link href="/news" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors">./news</Link>
            <Link href="/forums" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors">./forums</Link>
            <Link href="/tools" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors">./tools</Link>

            <Link href="/about" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors">./about</Link>
            <Link href="https://jerome.is-a.dev/contact" className="text-xs sm:text-sm hover:text-cyber-blue transition-colors" target="_blank" rel="noopener noreferrer">./contact</Link>
            
            {/* Tablet Admin Button */}
            <button 
              onClick={handleAdminToggle}
              className={`flex items-center space-x-1 text-xs sm:text-sm transition-all duration-300 ${
                isAdminMode 
                  ? 'text-cyber-pink' 
                  : 'text-cyber-green hover:text-cyber-blue'
              }`}
            >
              <FaCog className={isAdminMode ? 'animate-spin' : ''} />
              <span>{isAdminMode ? 'Admin' : 'Admin'}</span>
              {isAdminMode && (
                <div className="w-1.5 h-1.5 bg-cyber-pink rounded-full animate-pulse" />
              )}
            </button>
          </nav>
        </div>
      </header>

      {/* Admin Login Modal */}
      {showAdminModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-[200] p-4">
          <div className="bg-card-bg border border-cyber-green p-4 sm:p-6 rounded-lg max-w-md w-full">
            <h3 className="text-base sm:text-lg font-bold mb-3 sm:mb-4 text-center">
              <span data-text="ADMIN ACCESS REQUIRED">
                ADMIN ACCESS REQUIRED
              </span>
            </h3>
            {error && (
              <div className="mb-3 sm:mb-4 p-3 bg-red-500/20 border border-red-500 rounded text-red-400 text-xs sm:text-sm">
                {error}
              </div>
            )}
            <form onSubmit={handleAdminLogin}>
              <div className="mb-3 sm:mb-4 space-y-3">
                <input
                  type="text"
                  placeholder="Username"
                  value={loginForm.username}
                  onChange={(e) => setLoginForm({...loginForm, username: e.target.value})}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-2 sm:p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none text-sm sm:text-base"
                  required
                />
                <input
                  type="password"
                  placeholder="Password"
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-2 sm:p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none text-sm sm:text-base"
                  required
                />
              </div>
              <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-4">
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 bg-cyber-green text-black py-2 px-4 rounded hover:bg-cyber-blue transition-colors font-bold disabled:opacity-50 text-sm sm:text-base"
                >
                  {loading ? 'AUTHENTICATING...' : 'ACCESS'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowAdminModal(false);
                    setLoginForm({ username: '', password: '' });
                    setError('');
                  }}
                  className="flex-1 bg-transparent border border-cyber-green text-cyber-green py-2 px-4 rounded hover:bg-cyber-green hover:text-black transition-colors text-sm sm:text-base"
                >
                  ABORT
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Admin Setup Modal */}
      {showSetupModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-[200] p-4">
          <div className="bg-card-bg border border-cyber-green p-4 sm:p-6 rounded-lg max-w-md w-full">
            <h3 className="text-base sm:text-lg font-bold mb-3 sm:mb-4 text-center">
              <span data-text="ADMIN SETUP REQUIRED">
                ADMIN SETUP REQUIRED
              </span>
            </h3>
            <p className="text-xs sm:text-sm text-gray-400 mb-3 sm:mb-4 text-center">
              Create the first admin user for this system.
            </p>
            {error && (
              <div className="mb-3 sm:mb-4 p-3 bg-red-500/20 border border-red-500 rounded text-red-400 text-xs sm:text-sm">
                {error}
              </div>
            )}
            <form onSubmit={handleAdminSetup}>
              <div className="mb-3 sm:mb-4 space-y-3">
                <input
                  type="text"
                  placeholder="Setup Key"
                  value={setupForm.setupKey}
                  onChange={(e) => setSetupForm({...setupForm, setupKey: e.target.value})}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-2 sm:p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none text-sm sm:text-base"
                  required
                />
                <input
                  type="text"
                  placeholder="Admin Username"
                  value={setupForm.username}
                  onChange={(e) => setSetupForm({...setupForm, username: e.target.value})}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-2 sm:p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none text-sm sm:text-base"
                  required
                />
                <input
                  type="password"
                  placeholder="Password"
                  value={setupForm.password}
                  onChange={(e) => setSetupForm({...setupForm, password: e.target.value})}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-2 sm:p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none text-sm sm:text-base"
                  required
                />
                <input
                  type="password"
                  placeholder="Confirm Password"
                  value={setupForm.confirmPassword}
                  onChange={(e) => setSetupForm({...setupForm, confirmPassword: e.target.value})}
                  className="w-full bg-terminal-bg border border-cyber-green/50 p-2 sm:p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none text-sm sm:text-base"
                  required
                />
              </div>
              <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-4">
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 bg-cyber-green text-black py-2 px-4 rounded hover:bg-cyber-blue transition-colors font-bold disabled:opacity-50 text-sm sm:text-base"
                >
                  {loading ? 'CREATING...' : 'CREATE ADMIN'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowSetupModal(false);
                    setSetupForm({ username: '', password: '', confirmPassword: '', setupKey: '' });
                    setError('');
                  }}
                  className="flex-1 bg-transparent border border-cyber-green text-cyber-green py-2 px-4 rounded hover:bg-cyber-green hover:text-black transition-colors text-sm sm:text-base"
                >
                  CANCEL
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Search Modal */}
      <SearchModal 
        isOpen={showSearchModal} 
        onClose={() => setShowSearchModal(false)} 
      />
    </>
  );
};

export default Header;
