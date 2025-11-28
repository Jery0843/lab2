'use client';

import { useState } from 'react';
import { FaLock, FaEye, FaEyeSlash, FaSpinner } from 'react-icons/fa';

interface ActiveCTF403Props {
  writeupId: string;
  title: string;
  ctfName: string;
  onAccessGranted: (writeupData: any) => void;
}

const ActiveCTF403 = ({ writeupId, title, ctfName, onAccessGranted }: ActiveCTF403Props) => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [verificationToken, setVerificationToken] = useState('');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [emailLoading, setEmailLoading] = useState(false);
  const [otpLoading, setOtpLoading] = useState(false);
  const [emailError, setEmailError] = useState('');

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) return;
    
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/verify-ctf-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          writeupId,
          password,
          step: 'password'
        }),
      });

      const data = await response.json();

      if (response.ok && data.success && data.verificationToken) {
        setVerificationToken(data.verificationToken);
        setShowEmailModal(true);
        setError('');
      } else {
        setError(data.error || 'Invalid password');
      }
    } catch (error) {
      setError('Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSendOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;

    setEmailLoading(true);
    setEmailError('');

    try {
      const response = await fetch('/api/verify-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email.trim() })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setOtpSent(true);
      } else {
        setEmailError(data.error || 'Failed to send OTP');
      }
    } catch (err) {
      setEmailError('Network error occurred');
    } finally {
      setEmailLoading(false);
    }
  };

  const handleVerifyOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otp.trim()) return;

    setOtpLoading(true);
    setEmailError('');

    try {
      const response = await fetch('/api/verify-ctf-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          writeupId,
          password,
          email: email.trim(),
          name: name.trim() || undefined,
          otp: otp.trim(),
          step: 'complete',
          verificationToken
        }),
      });

      const data = await response.json();

      if (response.ok) {
        onAccessGranted(data.writeup);
        setShowEmailModal(false);
      } else {
        setEmailError(data.error || 'Access denied');
      }
    } catch (error) {
      setEmailError('Connection error. Please try again.');
    } finally {
      setOtpLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="rounded-2xl backdrop-blur-sm bg-black/20 light:bg-white/30 border border-white/10 p-8 max-w-md w-full">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-red-500/20 rounded-full mb-4">
            <FaLock className="text-red-400 text-2xl" />
          </div>
          <h1 className="text-2xl font-cyber font-bold text-red-400 mb-2">
            ACCESS RESTRICTED
          </h1>
          <p className="text-gray-400 mb-2">
            <span className="text-cyber-green">{title}</span>
          </p>
          <p className="text-sm text-gray-500">
            {ctfName}
          </p>
        </div>

        <div className="mb-6 p-4 bg-yellow-900/20 border border-yellow-500/50 rounded-lg">
          <p className="text-yellow-400 text-sm text-center">
            This writeup is password-protected while the challenge is active.
          </p>
        </div>

        <form onSubmit={handlePasswordSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-semibold mb-2 text-cyber-green">
              Challenge Password *
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-terminal-bg border border-cyber-green/50 p-3 pr-12 rounded text-cyber-green focus:border-cyber-green focus:outline-none"
                placeholder="Enter challenge password"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-cyber-green"
              >
                {showPassword ? <FaEyeSlash /> : <FaEye />}
              </button>
            </div>
          </div>

          {error && (
            <div className="p-3 bg-red-900/20 border border-red-500/50 rounded text-red-400 text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !password}
            className="w-full bg-cyber-green text-white py-3 px-4 rounded font-bold hover:bg-cyber-blue transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2"
          >
            {loading ? (
              <>
                <FaSpinner className="animate-spin text-white" />
                <span className="text-white">VERIFYING...</span>
              </>
            ) : (
              <span className="text-white">VERIFY PASSWORD</span>
            )}
          </button>
        </form>

        <div className="mt-6 p-4 bg-blue-900/20 border border-blue-500/50 rounded-lg text-center">
          <p className="text-blue-400 text-sm mb-3">
            Need access?
          </p>
          <a 
            href="/membership" 
            className="inline-block bg-cyber-purple text-white py-2 px-6 rounded font-bold hover:bg-cyber-blue transition-colors"
          >
            Get Membership
          </a>
        </div>
      </div>

      {/* Email Verification Modal */}
      {showEmailModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-[200] p-4">
          <div className="bg-card-bg border border-cyber-green p-6 rounded-lg max-w-md w-full">
            <h3 className="text-lg font-bold mb-4 text-center text-cyber-green">
              Email Verification Required
            </h3>
            
            {!otpSent ? (
              <form onSubmit={handleSendOTP}>
                <div className="mb-4 space-y-3">
                  <input
                    type="text"
                    placeholder="Your Name (Optional)"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none"
                  />
                  <input
                    type="email"
                    placeholder="Enter your email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none"
                    required
                  />
                </div>
                {emailError && (
                  <div className="mb-4 text-red-400 text-sm bg-red-400/10 border border-red-400/30 rounded-lg p-3">
                    {emailError}
                  </div>
                )}
                <div className="flex space-x-3">
                  <button
                    type="submit"
                    disabled={emailLoading || !email.trim()}
                    className="flex-1 bg-cyber-green text-white py-2 px-4 rounded hover:bg-cyber-blue transition-colors font-bold disabled:opacity-50"
                  >
                    {emailLoading ? (
                      <>
                        <FaSpinner className="animate-spin inline mr-2" />
                        Sending...
                      </>
                    ) : 'Send OTP'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowEmailModal(false)}
                    className="flex-1 bg-transparent border border-cyber-green text-cyber-green py-2 px-4 rounded hover:bg-cyber-green hover:text-white transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={handleVerifyOTP}>
                <p className="text-sm text-gray-300 mb-4 text-center">
                  OTP sent to {email}. Check your email and enter the code below.
                </p>
                <div className="mb-4">
                  <input
                    type="text"
                    placeholder="Enter 6-digit OTP"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="w-full bg-terminal-bg border border-cyber-green/50 p-3 rounded text-cyber-green focus:border-cyber-green focus:outline-none text-center text-lg tracking-widest"
                    maxLength={6}
                    required
                  />
                </div>
                {emailError && (
                  <div className="mb-4 text-red-400 text-sm bg-red-400/10 border border-red-400/30 rounded-lg p-3">
                    {emailError}
                  </div>
                )}
                <div className="flex space-x-3">
                  <button
                    type="submit"
                    disabled={otpLoading || otp.length !== 6}
                    className="flex-1 bg-cyber-green text-white py-2 px-4 rounded hover:bg-cyber-blue transition-colors font-bold disabled:opacity-50"
                  >
                    {otpLoading ? (
                      <>
                        <FaSpinner className="animate-spin inline mr-2" />
                        Verifying...
                      </>
                    ) : 'Verify OTP'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOtpSent(false);
                      setOtp('');
                      setEmailError('');
                    }}
                    className="flex-1 bg-transparent border border-cyber-green text-cyber-green py-2 px-4 rounded hover:bg-cyber-green hover:text-white transition-colors"
                  >
                    Back
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ActiveCTF403;