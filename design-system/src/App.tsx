import React, { useState, useEffect } from 'react';
import './App.css';

// Icons as SVG components
const SunIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="5"/>
    <line x1="12" y1="1" x2="12" y2="3"/>
    <line x1="12" y1="21" x2="12" y2="23"/>
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
    <line x1="1" y1="12" x2="3" y2="12"/>
    <line x1="21" y1="12" x2="23" y2="12"/>
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
  </svg>
);

const MoonIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
  </svg>
);

const SearchIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="11" cy="11" r="8"/>
    <path d="m21 21-4.35-4.35"/>
  </svg>
);

const CommandIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M18 3a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3 3 3 0 0 0 3-3 3 3 0 0 0-3-3H6a3 3 0 0 0-3 3 3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3 3 3 0 0 0-3 3 3 3 0 0 0 3 3h12a3 3 0 0 0 3-3 3 3 0 0 0-3-3z"/>
  </svg>
);

const TrendingUpIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
    <polyline points="17 6 23 6 23 12"/>
  </svg>
);

const TrendingDownIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/>
    <polyline points="17 18 23 18 23 12"/>
  </svg>
);

export default function App() {
  const [theme, setTheme] = useState<'light' | 'dark'>('dark');
  const [commandBarOpen, setCommandBarOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState('');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedDeal, setSelectedDeal] = useState<any>(null);

  useEffect(() => {
    document.documentElement.className = theme;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && !commandBarOpen) {
        e.preventDefault();
        setCommandBarOpen(true);
      }
      if (e.key === 'Escape' && commandBarOpen) {
        setCommandBarOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [commandBarOpen]);

  const metrics = [
    { id: 'revenue', label: 'Revenue', value: '$2.4M', change: 12.5, trending: 'up' },
    { id: 'customers', label: 'Customers', value: '1,284', change: 8.3, trending: 'up' },
    { id: 'efficiency', label: 'Efficiency', value: '94%', change: 2.1, trending: 'up' },
    { id: 'nps', label: 'NPS Score', value: '72', change: -3.2, trending: 'down' }
  ];

  const deals = [
    { id: 1, company: 'Acme Corp', amount: '$125,000', stage: 'Negotiation', probability: 80, daysInStage: 3 },
    { id: 2, company: 'TechStart Inc', amount: '$85,000', stage: 'Proposal', probability: 60, daysInStage: 5 },
    { id: 3, company: 'Global Systems', amount: '$250,000', stage: 'Discovery', probability: 30, daysInStage: 1 },
    { id: 4, company: 'Innovation Lab', amount: '$45,000', stage: 'Closed Won', probability: 100, daysInStage: 0 },
  ];

  const commands = [
    { id: 1, title: 'Create New Deal', shortcut: '⌘D', action: 'create-deal' },
    { id: 2, title: 'View Analytics', shortcut: '⌘A', action: 'view-analytics' },
    { id: 3, title: 'Export Report', shortcut: '⌘E', action: 'export-report' },
    { id: 4, title: 'Settings', shortcut: '⌘,', action: 'settings' },
  ];

  const filteredCommands = commands.filter(cmd =>
    cmd.title.toLowerCase().includes(commandQuery.toLowerCase())
  );

  return (
    <div className="app">
      {/* Command Bar Overlay */}
      {commandBarOpen && (
        <div className="command-bar-overlay" onClick={() => setCommandBarOpen(false)}>
          <div className="command-bar" onClick={e => e.stopPropagation()}>
            <div className="command-bar-input">
              <SearchIcon />
              <input
                type="text"
                placeholder="Type a command or search..."
                value={commandQuery}
                onChange={(e) => setCommandQuery(e.target.value)}
                autoFocus
              />
              <span className="command-hint">ESC to close</span>
            </div>
            <div className="command-results">
              {filteredCommands.map(cmd => (
                <div key={cmd.id} className="command-item">
                  <span>{cmd.title}</span>
                  <kbd>{cmd.shortcut}</kbd>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="header">
        <div className="header-left">
          <h1 className="logo">CoreFlow360</h1>
          <nav className="nav">
            <button
              className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
              onClick={() => setActiveTab('dashboard')}
            >
              Dashboard
            </button>
            <button
              className={`nav-item ${activeTab === 'pipeline' ? 'active' : ''}`}
              onClick={() => setActiveTab('pipeline')}
            >
              Pipeline
            </button>
            <button
              className={`nav-item ${activeTab === 'analytics' ? 'active' : ''}`}
              onClick={() => setActiveTab('analytics')}
            >
              Analytics
            </button>
          </nav>
        </div>
        <div className="header-right">
          <button
            className="command-trigger"
            onClick={() => setCommandBarOpen(true)}
          >
            <SearchIcon />
            <span>Search</span>
            <kbd>/</kbd>
          </button>
          <button
            className="theme-toggle"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          >
            {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="main">
        {activeTab === 'dashboard' && (
          <div className="dashboard">
            <div className="dashboard-header">
              <h2>Welcome back</h2>
              <p className="subtitle">Here's what's happening with your business today.</p>
            </div>

            {/* Metrics Grid */}
            <div className="metrics-grid">
              {metrics.map(metric => (
                <div key={metric.id} className="metric-card">
                  <div className="metric-header">
                    <span className="metric-label">{metric.label}</span>
                    <span className={`metric-change ${metric.trending}`}>
                      {metric.trending === 'up' ? <TrendingUpIcon /> : <TrendingDownIcon />}
                      {Math.abs(metric.change)}%
                    </span>
                  </div>
                  <div className="metric-value">{metric.value}</div>
                </div>
              ))}
            </div>

            {/* Chart Section */}
            <div className="chart-section">
              <div className="chart-header">
                <h3>Revenue Overview</h3>
                <div className="chart-controls">
                  <button className="chart-btn active">Week</button>
                  <button className="chart-btn">Month</button>
                  <button className="chart-btn">Year</button>
                </div>
              </div>
              <div className="chart-container">
                <div className="chart-placeholder">
                  <svg viewBox="0 0 400 200" className="chart">
                    <path
                      d="M 0,150 Q 100,100 200,120 T 400,80"
                      fill="none"
                      stroke="var(--accent)"
                      strokeWidth="2"
                    />
                    <path
                      d="M 0,150 Q 100,100 200,120 T 400,80 L 400,200 L 0,200 Z"
                      fill="var(--accent)"
                      opacity="0.1"
                    />
                  </svg>
                </div>
              </div>
            </div>

            {/* Recent Activity */}
            <div className="activity-section">
              <h3>Recent Activity</h3>
              <div className="activity-list">
                <div className="activity-item">
                  <div className="activity-dot"></div>
                  <div className="activity-content">
                    <p className="activity-text">New deal created with <strong>Acme Corp</strong></p>
                    <span className="activity-time">2 hours ago</span>
                  </div>
                </div>
                <div className="activity-item">
                  <div className="activity-dot"></div>
                  <div className="activity-content">
                    <p className="activity-text">Meeting scheduled with <strong>TechStart Inc</strong></p>
                    <span className="activity-time">5 hours ago</span>
                  </div>
                </div>
                <div className="activity-item">
                  <div className="activity-dot"></div>
                  <div className="activity-content">
                    <p className="activity-text">Proposal sent to <strong>Global Systems</strong></p>
                    <span className="activity-time">Yesterday</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'pipeline' && (
          <div className="pipeline">
            <div className="pipeline-header">
              <h2>Sales Pipeline</h2>
              <button className="btn-primary">Add Deal</button>
            </div>

            <div className="pipeline-board">
              {['Discovery', 'Proposal', 'Negotiation', 'Closed Won'].map(stage => (
                <div key={stage} className="pipeline-column">
                  <div className="column-header">
                    <h3>{stage}</h3>
                    <span className="column-count">
                      {deals.filter(d => d.stage === stage).length}
                    </span>
                  </div>
                  <div className="column-cards">
                    {deals
                      .filter(d => d.stage === stage)
                      .map(deal => (
                        <div
                          key={deal.id}
                          className="deal-card"
                          onClick={() => setSelectedDeal(deal)}
                        >
                          <div className="deal-header">
                            <h4>{deal.company}</h4>
                            <span className="deal-amount">{deal.amount}</span>
                          </div>
                          <div className="deal-footer">
                            <div className="probability-bar">
                              <div
                                className="probability-fill"
                                style={{ width: `${deal.probability}%` }}
                              />
                            </div>
                            <span className="deal-days">{deal.daysInStage}d</span>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="analytics">
            <div className="analytics-header">
              <h2>Analytics</h2>
              <div className="date-picker">
                <button className="date-btn">Last 30 Days</button>
              </div>
            </div>

            <div className="analytics-grid">
              <div className="analytics-card">
                <h3>Conversion Rate</h3>
                <div className="big-number">68%</div>
                <div className="trend up">+5% from last month</div>
              </div>
              <div className="analytics-card">
                <h3>Average Deal Size</h3>
                <div className="big-number">$87.5K</div>
                <div className="trend up">+12% from last month</div>
              </div>
              <div className="analytics-card">
                <h3>Sales Velocity</h3>
                <div className="big-number">21 days</div>
                <div className="trend down">-3 days from last month</div>
              </div>
              <div className="analytics-card">
                <h3>Win Rate</h3>
                <div className="big-number">42%</div>
                <div className="trend up">+8% from last month</div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}