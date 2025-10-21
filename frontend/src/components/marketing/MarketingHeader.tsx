import React, { useState } from 'react';
import { Link } from '@tanstack/react-router';
import { Menu, X } from 'lucide-react';
import { Button } from '../ui/button';

export function MarketingHeader() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 bg-white/80 backdrop-blur-lg border-b border-slate-200">
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-gradient-to-br from-brand-primary-600 to-brand-accent-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">CF</span>
            </div>
            <span className="font-bold text-xl text-slate-900">CoreFlow360</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            <Link to="/pricing" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              Pricing
            </Link>
            <Link to="/about" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              About
            </Link>
            <Link to="/help" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              Help
            </Link>
            <Link to="/contact" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              Contact
            </Link>
          </div>

          {/* CTA Buttons */}
          <div className="hidden md:flex items-center space-x-4">
            <Link to="/auth/login">
              <Button variant="ghost" size="sm">Login</Button>
            </Link>
            <Link to="/auth/register">
              <Button size="sm" className="bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 hover:from-brand-primary-700 hover:to-brand-accent-700">
                Start Free Trial
              </Button>
            </Link>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 text-slate-700 hover:text-brand-primary-600"
            aria-label="Toggle menu"
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-navigation"
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div id="mobile-navigation" className="md:hidden py-4 border-t border-slate-200">
            <nav className="flex flex-col space-y-4" aria-label="Mobile navigation">
              <Link to="/pricing" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                Pricing
              </Link>
              <Link to="/about" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                About
              </Link>
              <Link to="/help" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                Help
              </Link>
              <Link to="/contact" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                Contact
              </Link>
              <div className="pt-4 border-t border-slate-200 flex flex-col space-y-2">
                <Link to="/auth/login">
                  <Button variant="outline" className="w-full">Login</Button>
                </Link>
                <Link to="/auth/register">
                  <Button className="w-full bg-gradient-to-r from-brand-primary-600 to-brand-accent-600">
                    Start Free Trial
                  </Button>
                </Link>
              </div>
            </nav>
          </div>
        )}
      </nav>
    </header>
  );
}
