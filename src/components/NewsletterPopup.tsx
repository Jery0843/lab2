'use client';

import { useState, useEffect } from 'react';
import { FaTimes, FaEnvelope, FaUser, FaGlobe } from 'react-icons/fa';

interface NewsletterPopupProps {
  onClose: () => void;
}

const NewsletterPopup = ({ onClose }: NewsletterPopupProps) => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    country: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault();
  setLoading(true);
  setError(null);

  try {
    // Step 1: Validate email via Make.com
    const validationResponse = await fetch('https://hook.eu2.make.com/ejk7hpxxblt35bp7tza6mmfstnne5loy', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ 
        email: formData.email,
        name: formData.name,
        country: formData.country
      })
    });

    const validationData = await validationResponse.json();

    // Step 2: If validation fails, show error
    if (!validationResponse.ok || !validationData.valid) {
      setError(validationData.error || 'Invalid email address. Please use a permanent email.');
      setLoading(false);
      return;
    }

    // Step 3: If validation passes, save to database
    const response = await fetch('/api/newsletter', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });

    const data = await response.json();

    if (data.success) {
      setSuccess(true);
      localStorage.setItem('newsletterPopupStatus', 'submitted');
      // Close popup after 2 seconds
      setTimeout(() => {
        onClose();
      }, 2000);
    } else {
      setError(data.error || 'Failed to subscribe');
    }

  } catch (err) {
    setError('Network error. Please try again.');
  } finally {
    setLoading(false);
  }
};


  const countries = [
    'United States', 'United Kingdom', 'Canada', 'Australia', 'Germany',
    'France', 'Italy', 'Spain', 'Netherlands', 'Sweden', 'Norway',
    'Denmark', 'Finland', 'Japan', 'South Korea', 'Singapore',
    'India', 'Brazil', 'Mexico', 'Argentina', 'Other'
  ];

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="glass-panel rounded-lg max-w-md w-full shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-cyber-purple/30">
          <div className="flex items-center space-x-3">
            <FaEnvelope className="text-cyber-purple text-xl" />
            <h2 className="text-xl font-bold text-cyber-purple">Join Our Newsletter</h2>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-cyber-purple transition-colors p-1"
          >
            <FaTimes className="text-xl" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {success ? (
            <div className="text-center py-8">
              <div className="text-4xl mb-4">🎉</div>
              <h3 className="text-lg font-bold text-cyber-green mb-2">Welcome aboard!</h3>
              <p className="text-gray-400">Thank you for subscribing to our newsletter.</p>
            </div>
          ) : (
            <>
              <div className="mb-6">
                <p className="text-gray-300 text-sm leading-relaxed">
                  Stay updated with the latest cybersecurity insights, writeups, and exclusive content from 0xJerry&apos;s Lab.
                </p>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                {/* Name Field */}
                <div>
                  <label htmlFor="name" className="block text-sm font-medium text-gray-300 mb-2">
                    <FaUser className="inline mr-2" />
                    Full Name
                  </label>
                  <input
                    type="text"
                    id="name"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    required
                    className="w-full px-3 py-2 bg-terminal-bg border border-cyber-purple/30 rounded-lg text-cyber-green placeholder-gray-500 focus:border-cyber-purple focus:outline-none"
                    placeholder="Enter your full name"
                  />
                </div>

                {/* Email Field */}
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                    <FaEnvelope className="inline mr-2" />
                    Email Address
                  </label>
                  <input
                    type="email"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    required
                    className="w-full px-3 py-2 bg-terminal-bg border border-cyber-purple/30 rounded-lg text-cyber-green placeholder-gray-500 focus:border-cyber-purple focus:outline-none"
                    placeholder="your.email@example.com"
                  />
                </div>

                {/* Country Field */}
                <div>
                  <label htmlFor="country" className="block text-sm font-medium text-gray-300 mb-2">
                    <FaGlobe className="inline mr-2" />
                    Country
                  </label>
                  <select
                    id="country"
                    name="country"
                    value={formData.country}
                    onChange={handleInputChange}
                    required
                    className="w-full px-3 py-2 bg-terminal-bg border border-cyber-purple/30 rounded-lg text-cyber-green focus:border-cyber-purple focus:outline-none"
                  >
                    <option value="">Select your country</option>
                    {countries.map(country => (
                      <option key={country} value={country}>{country}</option>
                    ))}
                  </select>
                </div>

                {/* Error Message */}
                {error && (
                  <div className="text-red-400 text-sm bg-red-900/20 border border-red-500/30 rounded-lg p-3">
                    {error}
                  </div>
                )}

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-cyber-purple text-white py-3 px-4 rounded-lg font-bold hover:bg-cyber-pink transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? 'Subscribing...' : 'Subscribe to Newsletter'}
                </button>
              </form>

              {/* Footer */}
              <div className="mt-4 text-center">
                <p className="text-xs text-gray-500">
                  We respect your privacy. Unsubscribe at any time.
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default NewsletterPopup;
