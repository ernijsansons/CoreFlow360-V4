import React from 'react';
import { Link } from '@tanstack/react-router';
import { Github, Twitter, Linkedin } from 'lucide-react';

export function MarketingFooter() {
  return (
    <footer className="bg-slate-900 text-slate-300">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Company */}
          <div>
            <h3 className="font-bold text-white mb-4">Company</h3>
            <ul className="space-y-2">
              <li><Link to="/marketing/about" className="hover:text-white transition-colors">About</Link></li>
              <li><Link to="/marketing/contact" className="hover:text-white transition-colors">Contact</Link></li>
              <li><a href="#" className="hover:text-white transition-colors">Careers</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Press</a></li>
            </ul>
          </div>

          {/* Product */}
          <div>
            <h3 className="font-bold text-white mb-4">Product</h3>
            <ul className="space-y-2">
              <li><Link to="/marketing/products" className="hover:text-white transition-colors">Features</Link></li>
              <li><Link to="/marketing/pricing" className="hover:text-white transition-colors">Pricing</Link></li>
              <li><Link to="/marketing/enterprise" className="hover:text-white transition-colors">Enterprise</Link></li>
              <li><a href="#" className="hover:text-white transition-colors">API</a></li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="font-bold text-white mb-4">Resources</h3>
            <ul className="space-y-2">
              <li><a href="#" className="hover:text-white transition-colors">Documentation</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Blog</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Case Studies</a></li>
              <li><a href="#" className="hover:text-white transition-colors">Support</a></li>
            </ul>
          </div>

          {/* Legal */}
          <div>
            <h3 className="font-bold text-white mb-4">Legal</h3>
            <ul className="space-y-2">
              <li><Link to="/marketing/privacy" className="hover:text-white transition-colors">Privacy</Link></li>
              <li><Link to="/marketing/terms" className="hover:text-white transition-colors">Terms</Link></li>
              <li><Link to="/marketing/security" className="hover:text-white transition-colors">Security</Link></li>
              <li><a href="#" className="hover:text-white transition-colors">Cookies</a></li>
            </ul>
          </div>
        </div>

        <div className="mt-12 pt-8 border-t border-slate-800 flex flex-col md:flex-row justify-between items-center">
          <div className="flex items-center space-x-4 mb-4 md:mb-0">
            <div className="w-8 h-8 bg-gradient-to-br from-brand-primary-600 to-brand-accent-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-sm">CF</span>
            </div>
            <span className="text-sm">© 2025 CoreFlow360. All rights reserved.</span>
          </div>

          <div className="flex items-center space-x-6">
            <span className="text-xs text-slate-500">SOC 2 Certified</span>
            <span className="text-xs text-slate-500">ISO 27001</span>
            <span className="text-xs text-slate-500">GDPR Compliant</span>
          </div>

          <div className="flex items-center space-x-4 mt-4 md:mt-0">
            <a href="#" className="hover:text-white transition-colors" aria-label="Twitter">
              <Twitter size={20} />
            </a>
            <a href="#" className="hover:text-white transition-colors" aria-label="LinkedIn">
              <Linkedin size={20} />
            </a>
            <a href="#" className="hover:text-white transition-colors" aria-label="GitHub">
              <Github size={20} />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
