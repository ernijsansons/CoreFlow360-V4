import React from 'react';
import { ArrowRight } from 'lucide-react';
import { Button } from '../ui/button';

interface CTASectionProps {
  headline: string;
  subheadline?: string;
  ctaText?: string;
  variant?: 'gradient' | 'dark' | 'light';
}

export function CTASection({
  headline,
  subheadline,
  ctaText = "Start Your Free Trial",
  variant = 'gradient'
}: CTASectionProps) {
  const bg = variant === 'gradient' ? 'bg-gradient-to-r from-brand-primary-600 to-brand-accent-600' :
             variant === 'dark' ? 'bg-slate-900' : 'bg-slate-50';
  
  const textColor = variant === 'light' ? 'text-slate-900' : 'text-white';

  return (
    <section className={`py-24 ${bg}`}>
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <h2 className={`text-3xl sm:text-5xl font-bold ${textColor} mb-6`}>
          {headline}
        </h2>
        {subheadline && (
          <p className={`text-xl mb-10 ${variant === 'light' ? 'text-slate-600' : 'text-white/90'}`}>
            {subheadline}
          </p>
        )}
        <Button
          size="lg"
          className={variant === 'light'
            ? 'bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 hover:from-brand-primary-700 hover:to-brand-accent-700'
            : 'bg-white text-brand-primary-600 hover:bg-slate-50'
          }
        >
          {ctaText}
          <ArrowRight className="ml-2" size={20} />
        </Button>
      </div>
    </section>
  );
}
