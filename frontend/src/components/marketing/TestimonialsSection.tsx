import React from 'react';
import { Star, Quote } from 'lucide-react';

interface Testimonial {
  name: string;
  role: string;
  company: string;
  content: string;
  rating: number;
  image?: string;
}

const testimonials: Testimonial[] = [
  {
    name: 'Sarah Chen',
    role: 'Founder',
    company: 'TechStart Ventures',
    content:
      'CoreFlow360 handles all my accounting and CRM across 3 businesses. I focus on growth while AI agents handle the operations. Game-changer for serial entrepreneurs.',
    rating: 5,
  },
  {
    name: 'Marcus Rodriguez',
    role: 'CEO',
    company: 'Scale Digital',
    content:
      'Cut our operational overhead by 60%. The autonomous invoicing alone saves 8 hours per week. Best investment we made this year.',
    rating: 5,
  },
  {
    name: 'Emily Watson',
    role: 'Managing Director',
    company: 'Watson Consulting Group',
    content:
      'Managing 5 businesses used to require a full-time accountant. Now CoreFlow360 handles it all autonomously. Incredible platform.',
    rating: 5,
  },
];

export function TestimonialsSection() {
  return (
    <section className="py-16 bg-slate-50" aria-labelledby="testimonials-heading">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2
            id="testimonials-heading"
            className="text-3xl font-bold text-slate-900 sm:text-4xl mb-4"
          >
            Trusted by Serial Entrepreneurs
          </h2>
          <p className="text-lg text-slate-600 max-w-2xl mx-auto">
            Join ambitious founders who manage multiple businesses effortlessly
          </p>
        </div>

        <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
          {testimonials.map((testimonial, index) => (
            <TestimonialCard key={index} testimonial={testimonial} />
          ))}
        </div>

        {/* Social Proof Stats */}
        <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8 text-center border-t border-slate-200 pt-12">
          <div>
            <div className="text-3xl font-bold text-brand-primary-600">99.9%</div>
            <div className="text-sm text-slate-600 mt-1">Uptime</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-brand-primary-600">&lt;100ms</div>
            <div className="text-sm text-slate-600 mt-1">Response Time</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-brand-primary-600">15+</div>
            <div className="text-sm text-slate-600 mt-1">Integrations</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-brand-primary-600">24/7</div>
            <div className="text-sm text-slate-600 mt-1">Support</div>
          </div>
        </div>
      </div>
    </section>
  );
}

function TestimonialCard({ testimonial }: { testimonial: Testimonial }) {
  return (
    <article className="bg-white rounded-lg shadow-sm p-6 hover:shadow-md transition-shadow">
      {/* Quote Icon */}
      <div className="flex items-start mb-4">
        <Quote className="h-8 w-8 text-brand-primary-200 flex-shrink-0" aria-hidden="true" />
      </div>

      {/* Rating */}
      <div className="flex gap-1 mb-4" role="img" aria-label={`${testimonial.rating} out of 5 stars`}>
        {Array.from({ length: 5 }).map((_, i) => (
          <Star
            key={i}
            className={`h-4 w-4 ${
              i < testimonial.rating
                ? 'text-yellow-400 fill-yellow-400'
                : 'text-slate-300'
            }`}
            aria-hidden="true"
          />
        ))}
      </div>

      {/* Content */}
      <blockquote className="text-slate-700 mb-6 leading-relaxed">
        "{testimonial.content}"
      </blockquote>

      {/* Author */}
      <footer className="flex items-center gap-3">
        {testimonial.image ? (
          <img
            src={testimonial.image}
            alt=""
            className="h-12 w-12 rounded-full object-cover"
          />
        ) : (
          <div className="h-12 w-12 rounded-full bg-brand-primary-100 flex items-center justify-center">
            <span className="text-brand-primary-600 font-semibold text-lg">
              {testimonial.name.charAt(0)}
            </span>
          </div>
        )}

        <div>
          <cite className="not-italic font-semibold text-slate-900">
            {testimonial.name}
          </cite>
          <div className="text-sm text-slate-600">
            {testimonial.role}, {testimonial.company}
          </div>
        </div>
      </footer>
    </article>
  );
}

export default TestimonialsSection;
