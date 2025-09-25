/**
 * COMPONENT PLAYGROUND
 * Interactive environment to test and experiment with the design system
 */

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Moon, Sun, Code, Eye, Smartphone, Monitor, Tablet,
  Play, RotateCcw, Download, Share2, Settings
} from 'lucide-react';

// Import all components
import * as Primitives from '../components/primitives';
import * as SignatureInterfaces from '../components/signature-interfaces';
import * as PipelineCRM from '../components/pipeline-crm';
import * as FinancialDashboard from '../components/financial-dashboard';
import * as Mobile from '../mobile/mobile-experience';
import * as Interactions from '../interactions/paradigms';

// Import screens
import * as Screens from '../screens/key-screens';

// Device frames for responsive preview
const DeviceFrame: React.FC<{
  device: 'mobile' | 'tablet' | 'desktop';
  children: React.ReactNode;
}> = ({ device, children }) => {
  const frames = {
    mobile: 'w-[390px] h-[844px]',
    tablet: 'w-[768px] h-[1024px]',
    desktop: 'w-[1440px] h-[900px]'
  };

  return (
    <div className={`${frames[device]} bg-white dark:bg-black border border-black/8 dark:border-white/8 rounded-lg overflow-auto`}>
      {children}
    </div>
  );
};

// Component showcase panel
const ComponentShowcase: React.FC<{
  title: string;
  description: string;
  children: React.ReactNode;
  code?: string;
}> = ({ title, description, children, code }) => {
  const [showCode, setShowCode] = useState(false);

  return (
    <div className="border border-black/8 dark:border-white/8 rounded-lg overflow-hidden">
      <div className="p-4 border-b border-black/8 dark:border-white/8">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-[16px] font-medium text-black dark:text-white">
              {title}
            </h3>
            <p className="text-[13px] text-black/64 dark:text-white/64 mt-1">
              {description}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowCode(!showCode)}
              className={`p-2 rounded ${showCode ? 'bg-black dark:bg-white text-white dark:text-black' : 'hover:bg-black/4 dark:hover:bg-white/4'}`}
            >
              {showCode ? <Eye className="w-4 h-4" /> : <Code className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </div>

      <div className="p-8 bg-gray-50 dark:bg-gray-950">
        <AnimatePresence mode="wait">
          {showCode ? (
            <motion.pre
              key="code"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-[13px] text-black dark:text-white font-mono overflow-auto"
            >
              <code>{code || 'No code example available'}</code>
            </motion.pre>
          ) : (
            <motion.div
              key="preview"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              {children}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

// Main Playground App
export default function Playground() {
  const [theme, setTheme] = useState<'light' | 'dark'>('dark');
  const [device, setDevice] = useState<'mobile' | 'tablet' | 'desktop'>('desktop');
  const [activeSection, setActiveSection] = useState('primitives');

  // Sample data for components
  const sampleDeal: PipelineCRM.Deal = {
    id: '1',
    company: 'Acme Corp',
    amount: 125000,
    stage: 'negotiation',
    daysInStage: 3,
    probability: 80,
    owner: 'Alex Johnson',
    aiSuggestion: 'Schedule final review call this week'
  };

  const sampleMetric = {
    id: 'revenue',
    value: 2437650,
    label: 'Total Revenue',
    change: 12.5,
    trend: 'up' as const
  };

  const sections = [
    { id: 'primitives', label: 'Primitives' },
    { id: 'signature', label: 'Signature Interfaces' },
    { id: 'pipeline', label: 'Pipeline CRM' },
    { id: 'financial', label: 'Financial Dashboard' },
    { id: 'mobile', label: 'Mobile Experience' },
    { id: 'interactions', label: 'Interactions' },
    { id: 'screens', label: 'Full Screens' }
  ];

  React.useEffect(() => {
    document.documentElement.className = theme;
  }, [theme]);

  return (
    <Interactions.KeyboardNavigationProvider>
      <Interactions.UndoSystemProvider>
        <div className={`min-h-screen bg-white dark:bg-black ${theme}`}>
          {/* Header */}
          <header className="sticky top-0 z-50 bg-white/95 dark:bg-black/95 backdrop-blur-lg border-b border-black/8 dark:border-white/8">
            <div className="max-w-[1920px] mx-auto px-6 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-8">
                  <h1 className="text-[20px] font-medium text-black dark:text-white">
                    Design System Playground
                  </h1>
                  <nav className="flex gap-1">
                    {sections.map((section) => (
                      <button
                        key={section.id}
                        onClick={() => setActiveSection(section.id)}
                        className={`px-3 py-1.5 text-[13px] rounded transition-colors ${
                          activeSection === section.id
                            ? 'bg-black dark:bg-white text-white dark:text-black'
                            : 'text-black/64 dark:text-white/64 hover:text-black dark:hover:text-white'
                        }`}
                      >
                        {section.label}
                      </button>
                    ))}
                  </nav>
                </div>

                <div className="flex items-center gap-4">
                  {/* Device selector */}
                  <div className="flex gap-1 p-1 bg-black/4 dark:bg-white/4 rounded">
                    <button
                      onClick={() => setDevice('mobile')}
                      className={`p-2 rounded ${device === 'mobile' ? 'bg-white dark:bg-black' : ''}`}
                    >
                      <Smartphone className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setDevice('tablet')}
                      className={`p-2 rounded ${device === 'tablet' ? 'bg-white dark:bg-black' : ''}`}
                    >
                      <Tablet className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setDevice('desktop')}
                      className={`p-2 rounded ${device === 'desktop' ? 'bg-white dark:bg-black' : ''}`}
                    >
                      <Monitor className="w-4 h-4" />
                    </button>
                  </div>

                  {/* Theme toggle */}
                  <button
                    onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                    className="p-2 rounded hover:bg-black/4 dark:hover:bg-white/4"
                  >
                    {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                  </button>

                  {/* Actions */}
                  <button className="p-2 rounded hover:bg-black/4 dark:hover:bg-white/4">
                    <Download className="w-4 h-4" />
                  </button>
                  <button className="p-2 rounded hover:bg-black/4 dark:hover:bg-white/4">
                    <Share2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </header>

          {/* Main Content */}
          <main className="max-w-[1920px] mx-auto px-6 py-8">
            {/* Primitives Section */}
            {activeSection === 'primitives' && (
              <div className="space-y-8">
                <ComponentShowcase
                  title="Button Component"
                  description="The foundation of all interactions"
                  code={`<Button variant="primary" icon={<Save />} shortcut="⌘S">
  Save Changes
</Button>`}
                >
                  <div className="flex flex-wrap gap-3">
                    <Primitives.Button variant="primary">Primary</Primitives.Button>
                    <Primitives.Button variant="secondary">Secondary</Primitives.Button>
                    <Primitives.Button variant="ghost">Ghost</Primitives.Button>
                    <Primitives.Button loading>Loading</Primitives.Button>
                    <Primitives.Button disabled>Disabled</Primitives.Button>
                  </div>
                </ComponentShowcase>

                <ComponentShowcase
                  title="Input Component"
                  description="Text entry with intelligent labeling"
                  code={`<Input
  label="Email"
  type="email"
  icon={<Mail />}
  error={validationError}
/>`}
                >
                  <div className="space-y-4 max-w-md">
                    <Primitives.Input label="Email" type="email" />
                    <Primitives.Input label="Password" type="password" />
                    <Primitives.Input label="With Error" error="This field is required" />
                  </div>
                </ComponentShowcase>

                <ComponentShowcase
                  title="Card Component"
                  description="Container with depth and interaction"
                  code={`<Card interactive hoverable>
  Card content with hover effects
</Card>`}
                >
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Primitives.Card>Basic Card</Primitives.Card>
                    <Primitives.Card interactive>Interactive Card</Primitives.Card>
                    <Primitives.Card interactive hoverable>Hoverable Card</Primitives.Card>
                  </div>
                </ComponentShowcase>
              </div>
            )}

            {/* Signature Interfaces Section */}
            {activeSection === 'signature' && (
              <div className="space-y-8">
                <ComponentShowcase
                  title="Command Bar"
                  description="Universal control center - Press / to activate"
                  code={`<CommandBar
  onCommand={handleCommand}
  suggestions={aiPoweredSuggestions}
/>`}
                >
                  <div className="text-center py-8">
                    <Primitives.Text variant="body" color="secondary">
                      Press <kbd className="px-2 py-1 bg-black/8 dark:bg-white/8 rounded">/</kbd> to open the command bar
                    </Primitives.Text>
                  </div>
                  <SignatureInterfaces.CommandBar
                    suggestions={[
                      {
                        id: '1',
                        title: 'Create Invoice',
                        description: 'Start a new invoice',
                        action: () => console.log('Create invoice'),
                        shortcut: '⌘I'
                      }
                    ]}
                  />
                </ComponentShowcase>

                <ComponentShowcase
                  title="Intelligent Dashboard"
                  description="Context-aware metrics display"
                  code={`<IntelligentDashboard
  primaryMetric={revenueMetric}
  secondaryMetrics={kpis}
/>`}
                >
                  <SignatureInterfaces.IntelligentDashboard
                    primaryMetric={sampleMetric}
                    secondaryMetrics={[
                      { id: '1', value: 1284, label: 'Customers', change: 8.3, trend: 'up' },
                      { id: '2', value: 94, label: 'Efficiency %', change: 2.1, trend: 'up' }
                    ]}
                  />
                </ComponentShowcase>
              </div>
            )}

            {/* Pipeline CRM Section */}
            {activeSection === 'pipeline' && (
              <ComponentShowcase
                title="Pipeline View"
                description="Deal flow visualization reimagined"
                code={`<Pipeline
  stages={dealStages}
  onDealMove={handleDealMove}
/>`}
              >
                <PipelineCRM.Pipeline
                  stages={[
                    { id: '1', title: 'Prospect', deals: [sampleDeal] },
                    { id: '2', title: 'Qualified', deals: [] },
                    { id: '3', title: 'Proposal', deals: [] }
                  ]}
                />
              </ComponentShowcase>
            )}

            {/* Financial Dashboard Section */}
            {activeSection === 'financial' && (
              <div className="space-y-8">
                <ComponentShowcase
                  title="Metric Card"
                  description="Single number with maximum impact"
                  code={`<MetricCard
  title="Revenue"
  value={2437650}
  format="currency"
  change={12.5}
/>`}
                >
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <FinancialDashboard.MetricCard
                      title="Revenue"
                      value={2437650}
                      format="currency"
                      change={12.5}
                    />
                    <FinancialDashboard.MetricCard
                      title="Efficiency"
                      value={94.3}
                      format="percentage"
                      change={2.1}
                    />
                    <FinancialDashboard.MetricCard
                      title="Customers"
                      value={1284}
                      format="number"
                      change={8.3}
                    />
                  </div>
                </ComponentShowcase>
              </div>
            )}

            {/* Mobile Experience Section */}
            {activeSection === 'mobile' && (
              <ComponentShowcase
                title="Mobile Dashboard"
                description="Enterprise power in your pocket"
                code={`<MobileDashboard />`}
              >
                <DeviceFrame device="mobile">
                  <Mobile.MobileDashboard />
                </DeviceFrame>
              </ComponentShowcase>
            )}

            {/* Full Screens Section */}
            {activeSection === 'screens' && (
              <ComponentShowcase
                title="Complete Application Screens"
                description="Full experiences ready for production"
                code={`<DashboardScreen />`}
              >
                <DeviceFrame device={device}>
                  <Screens.DashboardScreen />
                </DeviceFrame>
              </ComponentShowcase>
            )}
          </main>
        </div>
      </Interactions.UndoSystemProvider>
    </Interactions.KeyboardNavigationProvider>
  );
}