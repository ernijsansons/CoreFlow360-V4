import React from 'react';
import { LucideIcon } from 'lucide-react';
import * as Icons from 'lucide-react';

interface Feature {
  icon: string;
  title: string;
  description: string;
}

interface FeatureGridProps {
  features: Feature[];
  columns?: 2 | 3 | 4;
}

export function FeatureGrid({ features, columns = 3 }: FeatureGridProps) {
  const gridCols = {
    2: 'md:grid-cols-2',
    3: 'md:grid-cols-3',
    4: 'md:grid-cols-4'
  };

  return (
    <section className="py-24 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className={`grid grid-cols-1 ${gridCols[columns]} gap-12`}>
          {features.map((feature, index) => {
            const iconKey = feature.icon as keyof typeof Icons;
            const IconComponent = Icons[iconKey] as LucideIcon | undefined;
            
            return (
              <div
                key={index}
                className="group relative p-8 rounded-2xl border border-slate-200 hover:border-brand-primary-300 hover:shadow-lg transition-all duration-300"
              >
                <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-brand-primary-600 to-brand-accent-600 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                  {IconComponent && <IconComponent className="text-white" size={24} />}
                </div>
                <h3 className="text-xl font-bold text-slate-900 mb-3">
                  {feature.title}
                </h3>
                <p className="text-slate-600 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
