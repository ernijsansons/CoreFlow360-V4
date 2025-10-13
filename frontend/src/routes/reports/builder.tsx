/**
 * Advanced Reporting & Custom Dashboard Builder
 * Create custom reports and dashboards with drag-and-drop widgets
 */

import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { MainLayout } from '@/layouts/main-layout';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  LayoutDashboard,
  Plus,
  BarChart3,
  LineChart,
  PieChart,
  Table as TableIcon,
  TrendingUp,
  DollarSign,
  Users,
  Target,
  Calendar,
  Filter,
  Download,
  Save,
  Eye,
  Settings,
  Trash2,
  GripVertical,
  Maximize2,
  Copy,
  Share2,
  Clock
} from 'lucide-react';

export const Route = createFileRoute('/reports/builder')({
  component: ReportBuilderPage,
});

interface Widget {
  id: string;
  type: 'chart' | 'metric' | 'table' | 'goal';
  title: string;
  size: 'small' | 'medium' | 'large' | 'full';
  config: {
    chartType?: 'bar' | 'line' | 'pie' | 'area';
    metric?: string;
    dataSource?: string;
    filters?: any[];
    timeRange?: string;
  };
  position: { x: number; y: number };
}

interface Dashboard {
  id: string;
  name: string;
  description?: string;
  widgets: Widget[];
  layout: 'grid' | 'flexible';
  shared: boolean;
  createdAt: string;
  updatedAt: string;
}

function ReportBuilderPage() {
  const [dashboards, setDashboards] = useState<Dashboard[]>([
    {
      id: 'd1',
      name: 'Sales Performance',
      description: 'Track sales metrics and pipeline health',
      widgets: [
        {
          id: 'w1',
          type: 'metric',
          title: 'Total Revenue',
          size: 'small',
          config: { metric: 'revenue', timeRange: '30d' },
          position: { x: 0, y: 0 },
        },
        {
          id: 'w2',
          type: 'chart',
          title: 'Revenue Trend',
          size: 'medium',
          config: { chartType: 'line', dataSource: 'deals', timeRange: '30d' },
          position: { x: 1, y: 0 },
        },
      ],
      layout: 'grid',
      shared: false,
      createdAt: '2025-01-01T00:00:00Z',
      updatedAt: '2025-01-10T00:00:00Z',
    },
  ]);

  const [selectedDashboard, setSelectedDashboard] = useState<Dashboard | null>(dashboards[0]);
  const [isEditing, setIsEditing] = useState(false);
  const [showWidgetPicker, setShowWidgetPicker] = useState(false);

  const widgetTypes = [
    {
      type: 'chart',
      name: 'Chart',
      icon: BarChart3,
      description: 'Visualize data with charts',
      variants: [
        { id: 'bar', name: 'Bar Chart', icon: BarChart3 },
        { id: 'line', name: 'Line Chart', icon: LineChart },
        { id: 'pie', name: 'Pie Chart', icon: PieChart },
      ],
    },
    {
      type: 'metric',
      name: 'Metric Card',
      icon: TrendingUp,
      description: 'Display key metrics',
    },
    {
      type: 'table',
      name: 'Data Table',
      icon: TableIcon,
      description: 'Show detailed data',
    },
    {
      type: 'goal',
      name: 'Goal Tracker',
      icon: Target,
      description: 'Track goals and targets',
    },
  ];

  const dataSources = [
    { id: 'deals', name: 'Deals', icon: Target },
    { id: 'contacts', name: 'Contacts', icon: Users },
    { id: 'revenue', name: 'Revenue', icon: DollarSign },
    { id: 'activities', name: 'Activities', icon: Calendar },
  ];

  const addWidget = (type: string) => {
    if (!selectedDashboard) return;

    const newWidget: Widget = {
      id: `w${Date.now()}`,
      type: type as any,
      title: `New ${type.charAt(0).toUpperCase() + type.slice(1)}`,
      size: 'medium',
      config: {},
      position: { x: selectedDashboard.widgets.length % 3, y: Math.floor(selectedDashboard.widgets.length / 3) },
    };

    const updatedDashboard = {
      ...selectedDashboard,
      widgets: [...selectedDashboard.widgets, newWidget],
    };

    setSelectedDashboard(updatedDashboard);
    setDashboards(dashboards.map((d) => (d.id === selectedDashboard.id ? updatedDashboard : d)));
    setShowWidgetPicker(false);
  };

  const removeWidget = (widgetId: string) => {
    if (!selectedDashboard) return;

    const updatedDashboard = {
      ...selectedDashboard,
      widgets: selectedDashboard.widgets.filter((w) => w.id !== widgetId),
    };

    setSelectedDashboard(updatedDashboard);
    setDashboards(dashboards.map((d) => (d.id === selectedDashboard.id ? updatedDashboard : d)));
  };

  const saveDashboard = () => {
    const event = new CustomEvent('show-toast', {
      detail: { message: 'Dashboard saved successfully', type: 'success' }
    });
    window.dispatchEvent(event);
    setIsEditing(false);
  };

  const exportDashboard = () => {
    const data = JSON.stringify(selectedDashboard, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dashboard-${selectedDashboard?.id}.json`;
    a.click();
    URL.revokeObjectURL(url);

    const event = new CustomEvent('show-toast', {
      detail: { message: 'Dashboard exported', type: 'success' }
    });
    window.dispatchEvent(event);
  };

  const getWidgetIcon = (type: string) => {
    switch (type) {
      case 'chart':
        return <BarChart3 className="w-5 h-5" />;
      case 'metric':
        return <TrendingUp className="w-5 h-5" />;
      case 'table':
        return <TableIcon className="w-5 h-5" />;
      case 'goal':
        return <Target className="w-5 h-5" />;
      default:
        return <LayoutDashboard className="w-5 h-5" />;
    }
  };

  const getSizeClass = (size: string) => {
    switch (size) {
      case 'small':
        return 'lg:col-span-1';
      case 'medium':
        return 'lg:col-span-2';
      case 'large':
        return 'lg:col-span-3';
      case 'full':
        return 'lg:col-span-4';
      default:
        return 'lg:col-span-2';
    }
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-100 dark:bg-indigo-900/20 rounded-lg">
              <LayoutDashboard className="w-6 h-6 text-indigo-600 dark:text-indigo-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Dashboard Builder</h1>
              <p className="text-muted-foreground mt-1">
                Create custom reports and dashboards with advanced visualizations
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {selectedDashboard && (
              <>
                <Button variant="outline" size="sm" onClick={() => setIsEditing(!isEditing)}>
                  {isEditing ? (
                    <>
                      <Eye className="w-4 h-4 mr-2" />
                      Preview
                    </>
                  ) : (
                    <>
                      <Settings className="w-4 h-4 mr-2" />
                      Edit
                    </>
                  )}
                </Button>
                <Button variant="outline" size="sm" onClick={exportDashboard}>
                  <Download className="w-4 h-4 mr-2" />
                  Export
                </Button>
                <Button size="sm" onClick={saveDashboard}>
                  <Save className="w-4 h-4 mr-2" />
                  Save
                </Button>
              </>
            )}
          </div>
        </div>

        {/* Dashboard Selector */}
        <Card className="p-4">
          <div className="flex items-center gap-4">
            <select
              value={selectedDashboard?.id || ''}
              onChange={(e) => {
                const dashboard = dashboards.find((d) => d.id === e.target.value);
                setSelectedDashboard(dashboard || null);
              }}
              className="h-10 px-3 rounded-md border border-input bg-background flex-1 max-w-md"
            >
              {dashboards.map((dashboard) => (
                <option key={dashboard.id} value={dashboard.id}>
                  {dashboard.name}
                </option>
              ))}
            </select>
            <Button size="sm" variant="outline">
              <Plus className="w-4 h-4 mr-2" />
              New Dashboard
            </Button>
          </div>
        </Card>

        {/* Widget Picker */}
        {isEditing && showWidgetPicker && (
          <Card className="p-6 border-2 border-primary">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Add Widget</h3>
              <Button variant="ghost" size="sm" onClick={() => setShowWidgetPicker(false)}>
                ✕
              </Button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {widgetTypes.map((widgetType) => (
                <button
                  key={widgetType.type}
                  onClick={() => addWidget(widgetType.type)}
                  className="p-4 border-2 border-border rounded-lg text-left hover:border-primary transition-colors"
                >
                  <widgetType.icon className="w-8 h-8 text-primary mb-2" />
                  <h4 className="font-semibold mb-1">{widgetType.name}</h4>
                  <p className="text-sm text-muted-foreground">{widgetType.description}</p>
                </button>
              ))}
            </div>
          </Card>
        )}

        {/* Dashboard Canvas */}
        {selectedDashboard && (
          <>
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold">{selectedDashboard.name}</h2>
                {selectedDashboard.description && (
                  <p className="text-sm text-muted-foreground">{selectedDashboard.description}</p>
                )}
              </div>
              {isEditing && (
                <Button size="sm" onClick={() => setShowWidgetPicker(true)}>
                  <Plus className="w-4 h-4 mr-2" />
                  Add Widget
                </Button>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
              {selectedDashboard.widgets.map((widget) => (
                <Card
                  key={widget.id}
                  className={`p-6 relative ${getSizeClass(widget.size)} ${
                    isEditing ? 'border-2 border-dashed border-primary' : ''
                  }`}
                >
                  {isEditing && (
                    <div className="absolute top-2 right-2 flex gap-1">
                      <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                        <GripVertical className="w-4 h-4" />
                      </Button>
                      <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                        <Settings className="w-4 h-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0"
                        onClick={() => removeWidget(widget.id)}
                      >
                        <Trash2 className="w-4 h-4 text-red-500" />
                      </Button>
                    </div>
                  )}

                  <div className="flex items-center gap-2 mb-4">
                    <div className="p-2 bg-primary/10 rounded-lg">
                      {getWidgetIcon(widget.type)}
                    </div>
                    <h3 className="font-semibold">{widget.title}</h3>
                  </div>

                  {/* Widget Content */}
                  {widget.type === 'metric' && (
                    <div>
                      <p className="text-4xl font-bold mb-2">$127.5K</p>
                      <div className="flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
                        <TrendingUp className="w-4 h-4" />
                        <span>+12.5% vs last month</span>
                      </div>
                    </div>
                  )}

                  {widget.type === 'chart' && (
                    <div className="h-48 flex items-end justify-between gap-2">
                      {[65, 80, 70, 85, 90, 75, 95].map((height, idx) => (
                        <div
                          key={idx}
                          className="flex-1 bg-primary rounded-t transition-all hover:opacity-80"
                          style={{ height: `${height}%` }}
                        />
                      ))}
                    </div>
                  )}

                  {widget.type === 'table' && (
                    <div className="space-y-2">
                      {['Deal A', 'Deal B', 'Deal C'].map((item, idx) => (
                        <div key={idx} className="flex items-center justify-between p-2 bg-muted rounded">
                          <span className="text-sm font-medium">{item}</span>
                          <span className="text-sm text-muted-foreground">
                            ${(45000 + idx * 5000).toLocaleString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  {widget.type === 'goal' && (
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium">Q1 Revenue Goal</span>
                        <span className="text-sm font-bold">78%</span>
                      </div>
                      <div className="w-full h-3 bg-muted rounded-full overflow-hidden">
                        <div className="h-full bg-primary transition-all" style={{ width: '78%' }} />
                      </div>
                      <p className="text-xs text-muted-foreground mt-2">
                        $780K of $1M target
                      </p>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          </>
        )}

        {/* Data Sources */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Filter className="w-5 h-5 text-primary" />
            Data Sources & Filters
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {dataSources.map((source) => (
              <div key={source.id} className="p-3 border border-border rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <source.icon className="w-4 h-4 text-primary" />
                  <span className="font-medium text-sm">{source.name}</span>
                </div>
                <Button variant="outline" size="sm" className="w-full">
                  Configure
                </Button>
              </div>
            ))}
          </div>
        </Card>

        {/* Saved Dashboards */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Saved Dashboards</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {dashboards.map((dashboard) => (
              <div
                key={dashboard.id}
                className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                  selectedDashboard?.id === dashboard.id
                    ? 'border-primary bg-primary/5'
                    : 'border-border hover:border-primary/50'
                }`}
                onClick={() => setSelectedDashboard(dashboard)}
              >
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-semibold">{dashboard.name}</h4>
                  <div className="flex gap-1">
                    <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                      <Copy className="w-3 h-3" />
                    </Button>
                    <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                      <Share2 className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
                {dashboard.description && (
                  <p className="text-sm text-muted-foreground mb-2">{dashboard.description}</p>
                )}
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span>{dashboard.widgets.length} widgets</span>
                  <span>•</span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(dashboard.updatedAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </MainLayout>
  );
}
