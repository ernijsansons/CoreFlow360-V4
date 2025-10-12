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
            <Link to="/marketing/products" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              Products
            </Link>
            <Link to="/marketing/pricing" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              Pricing
            </Link>
            <Link to="/marketing/enterprise" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              Enterprise
            </Link>
            <Link to="/marketing/about" className="text-slate-700 hover:text-brand-primary-600 font-medium transition-colors">
              About
            </Link>
          </div>

          {/* CTA Buttons */}
          <div className="hidden md:flex items-center space-x-4">
            <Link to="/login">
              <Button variant="ghost" size="sm">Login</Button>
            </Link>
            <Link to="/register">
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
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        {/* Mobile Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden py-4 border-t border-slate-200">
            <div className="flex flex-col space-y-4">
              <Link to="/marketing/products" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                Products
              </Link>
              <Link to="/marketing/pricing" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                Pricing
              </Link>
              <Link to="/marketing/enterprise" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                Enterprise
              </Link>
              <Link to="/marketing/about" className="text-slate-700 hover:text-brand-primary-600 font-medium">
                About
              </Link>
              <div className="pt-4 border-t border-slate-200 flex flex-col space-y-2">
                <Link to="/login">
                  <Button variant="outline" className="w-full">Login</Button>
                </Link>
                <Link to="/register">
                  <Button className="w-full bg-gradient-to-r from-brand-primary-600 to-brand-accent-600">
                    Start Free Trial
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        )}
      </nav>
    </header>
  );
}
