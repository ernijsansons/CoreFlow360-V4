/**
 * MCP COMPONENT GENERATOR
 * Templates for Figma Dev Mode MCP Server code generation
 * These templates are used when #get_code is called in Figma
 */

interface ComponentTemplate {
  name: string;
  figmaNodeType: string;
  generateCode: (props: FigmaNodeProps) => string;
}

interface FigmaNodeProps {
  width?: number | string;
  height?: number | string;
  fills?: any[];
  strokes?: any[];
  effects?: any[];
  cornerRadius?: number;
  padding?: { top: number; right: number; bottom: number; left: number };
  layoutMode?: 'HORIZONTAL' | 'VERTICAL' | 'NONE';
  primaryAxisAlignItems?: string;
  counterAxisAlignItems?: string;
  itemSpacing?: number;
  children?: any[];
  text?: string;
  fontSize?: number;
  fontWeight?: number;
  lineHeight?: number;
  letterSpacing?: number;
  textAlignHorizontal?: string;
  opacity?: number;
}

// Button Component Template
export const ButtonTemplate: ComponentTemplate = {
  name: 'Button',
  figmaNodeType: 'COMPONENT',
  generateCode: (props) => {
    const { text, width, height } = props;
    const isSmall = height && height < 36;
    const isPrimary = props.fills?.[0]?.color?.r === 0; // Black fill = primary

    return `<Button
  variant="${isPrimary ? 'primary' : 'secondary'}"
  size="${isSmall ? 'small' : 'default'}"
  ${width === 'FILL' ? 'className="w-full"' : ''}
>
  ${text || 'Button Text'}
</Button>`;
  }
};

// Input Component Template
export const InputTemplate: ComponentTemplate = {
  name: 'Input',
  figmaNodeType: 'COMPONENT',
  generateCode: (props) => {
    const { text, width } = props;
    const hasIcon = props.children?.some(child => child.type === 'VECTOR');

    return `<Input
  label="${text || 'Label'}"
  placeholder="Enter ${text?.toLowerCase() || 'text'}..."
  ${hasIcon ? 'icon={<Icon />}' : ''}
  ${width === 'FILL' ? 'className="w-full"' : ''}
/>`;
  }
};

// Card Component Template
export const CardTemplate: ComponentTemplate = {
  name: 'Card',
  figmaNodeType: 'FRAME',
  generateCode: (props) => {
    const { padding, cornerRadius, effects } = props;
    const hasHover = effects?.some(e => e.type === 'DROP_SHADOW');

    return `<Card
  ${hasHover ? 'interactive' : ''}
  ${hasHover ? 'hoverable' : ''}
  className="${padding ? `p-${Math.round(padding.top / 4)}` : 'p-5'}"
>
  {/* Card content */}
</Card>`;
  }
};

// Command Bar Template
export const CommandBarTemplate: ComponentTemplate = {
  name: 'CommandBar',
  figmaNodeType: 'COMPONENT',
  generateCode: () => {
    return `<CommandBar
  onCommand={handleCommand}
  suggestions={[
    {
      id: '1',
      title: 'Create new invoice',
      description: 'Start a new invoice draft',
      action: () => console.log('Create invoice'),
      shortcut: '⌘I',
      icon: <DollarSign className="w-4 h-4" />
    },
    // Add more suggestions
  ]}
  placeholder="Type '/' for commands or search..."
/>`;
  }
};

// Data Table Template
export const DataTableTemplate: ComponentTemplate = {
  name: 'DataTable',
  figmaNodeType: 'FRAME',
  generateCode: () => {
    return `<DataTable
  columns={[
    { key: 'name', title: 'Name', sortable: true },
    { key: 'value', title: 'Value', align: 'right', sortable: true },
    { key: 'status', title: 'Status', render: (val) => <Badge>{val}</Badge> }
  ]}
  data={tableData}
  onRowClick={(row) => handleRowClick(row)}
  onSelectionChange={(rows) => setSelectedRows(rows)}
/>`;
  }
};

// Dashboard Metric Template
export const MetricCardTemplate: ComponentTemplate = {
  name: 'MetricCard',
  figmaNodeType: 'COMPONENT',
  generateCode: (props) => {
    const { text } = props;
    const lines = text?.split('\n') || [];
    const value = lines[0] || '$0';
    const label = lines[1] || 'Metric';

    return `<MetricCard
  title="${label}"
  value={${value.startsWith('$') ? value.slice(1) : value}}
  format="${value.startsWith('$') ? 'currency' : value.includes('%') ? 'percentage' : 'number'}"
  change={12.5}
  changeLabel="vs last period"
  icon={<TrendingUp className="w-4 h-4" />}
/>`;
  }
};

// Pipeline Stage Template
export const PipelineStageTemplate: ComponentTemplate = {
  name: 'PipelineStage',
  figmaNodeType: 'FRAME',
  generateCode: () => {
    return `<Pipeline
  stages={[
    {
      id: 'prospect',
      title: 'Prospect',
      deals: prospectDeals
    },
    {
      id: 'qualified',
      title: 'Qualified',
      deals: qualifiedDeals
    },
    // Add more stages
  ]}
  onDealMove={(dealId, fromStage, toStage) => handleDealMove(dealId, fromStage, toStage)}
  onDealClick={(deal) => handleDealClick(deal)}
/>`;
  }
};

// Mobile Component Template
export const MobileComponentTemplate: ComponentTemplate = {
  name: 'MobileComponent',
  figmaNodeType: 'FRAME',
  generateCode: (props) => {
    const { width } = props;
    const isMobile = width && width < 768;

    if (isMobile) {
      return `<MobileCard
  onPress={() => handlePress()}
  swipeable
  onSwipeLeft={() => handleSwipeLeft()}
  onSwipeRight={() => handleSwipeRight()}
>
  {/* Mobile content */}
</MobileCard>`;
    }

    return `<Card interactive hoverable>
  {/* Desktop content */}
</Card>`;
  }
};

// Chart Template
export const ChartTemplate: ComponentTemplate = {
  name: 'Chart',
  figmaNodeType: 'FRAME',
  generateCode: (props) => {
    const hasDonut = props.children?.some(child => child.type === 'ELLIPSE');

    if (hasDonut) {
      return `<DonutChart
  data={[
    { label: 'Category A', value: 45, color: '#0066FF' },
    { label: 'Category B', value: 30, color: '#00C851' },
    { label: 'Category C', value: 25, color: '#FFBB33' }
  ]}
  size={200}
  thickness={30}
  centerContent={
    <div className="text-center">
      <div className="text-[20px] font-medium">Total</div>
      <div className="text-[13px] text-black/64">100%</div>
    </div>
  }
/>`;
    }

    return `<LineChart
  data={chartData}
  height={200}
  color="#0066FF"
  fillOpacity={0.05}
  showGrid
  animate
/>`;
  }
};

// Layout Template
export const LayoutTemplate: ComponentTemplate = {
  name: 'Layout',
  figmaNodeType: 'FRAME',
  generateCode: (props) => {
    const { layoutMode, itemSpacing, padding } = props;

    if (layoutMode === 'HORIZONTAL') {
      return `<div className="flex gap-${itemSpacing ? Math.round(itemSpacing / 4) : 4} p-${padding ? Math.round(padding.top / 4) : 0}">
  {/* Horizontal layout content */}
</div>`;
    }

    if (layoutMode === 'VERTICAL') {
      return `<div className="flex flex-col gap-${itemSpacing ? Math.round(itemSpacing / 4) : 4} p-${padding ? Math.round(padding.top / 4) : 0}">
  {/* Vertical layout content */}
</div>`;
    }

    return `<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
  {/* Grid layout content */}
</div>`;
  }
};

// Form Template
export const FormTemplate: ComponentTemplate = {
  name: 'Form',
  figmaNodeType: 'FRAME',
  generateCode: () => {
    return `<form onSubmit={handleSubmit} className="space-y-6">
  <Input
    label="Email"
    type="email"
    value={formData.email}
    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
    icon={<Mail className="w-4 h-4" />}
  />

  <Input
    label="Password"
    type="password"
    value={formData.password}
    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
    icon={<Lock className="w-4 h-4" />}
  />

  <Button type="submit" variant="primary" className="w-full">
    Submit
  </Button>
</form>`;
  }
};

// Navigation Template
export const NavigationTemplate: ComponentTemplate = {
  name: 'Navigation',
  figmaNodeType: 'FRAME',
  generateCode: (props) => {
    const { width } = props;
    const isMobile = width && width < 768;

    if (isMobile) {
      return `<MobileNavigation
  activeTab={activeTab}
  onTabChange={(tab) => setActiveTab(tab)}
/>`;
    }

    return `<nav className="flex items-center gap-6">
  {navItems.map((item) => (
    <button
      key={item.id}
      onClick={() => handleNavigation(item.id)}
      className={activeTab === item.id ? 'text-black dark:text-white' : 'text-black/36 dark:text-white/36'}
    >
      {item.label}
    </button>
  ))}
</nav>`;
  }
};

// Empty State Template
export const EmptyStateTemplate: ComponentTemplate = {
  name: 'EmptyState',
  figmaNodeType: 'FRAME',
  generateCode: () => {
    return `<div className="flex flex-col items-center justify-center p-12 text-center">
  <div className="w-16 h-16 bg-black/4 dark:bg-white/4 rounded-full flex items-center justify-center mb-4">
    <Icon className="w-8 h-8 text-black/36 dark:text-white/36" />
  </div>
  <Text variant="heading" weight="medium" className="mb-2">
    No data yet
  </Text>
  <Text variant="body" color="secondary" className="mb-6 max-w-md">
    Get started by creating your first item
  </Text>
  <Button variant="primary" icon={<Plus className="w-4 h-4" />}>
    Create New
  </Button>
</div>`;
  }
};

// Master template registry
export const ComponentTemplates: ComponentTemplate[] = [
  ButtonTemplate,
  InputTemplate,
  CardTemplate,
  CommandBarTemplate,
  DataTableTemplate,
  MetricCardTemplate,
  PipelineStageTemplate,
  MobileComponentTemplate,
  ChartTemplate,
  LayoutTemplate,
  FormTemplate,
  NavigationTemplate,
  EmptyStateTemplate
];

// Template matcher function for MCP
export function matchTemplate(figmaNode: any): ComponentTemplate | null {
  // Match by component name first
  const componentName = figmaNode.name?.toLowerCase();

  for (const template of ComponentTemplates) {
    if (componentName?.includes(template.name.toLowerCase())) {
      return template;
    }
  }

  // Match by node type and properties
  if (figmaNode.type === 'COMPONENT' || figmaNode.type === 'COMPONENT_INSTANCE') {
    if (figmaNode.children?.some((child: any) => child.type === 'TEXT')) {
      return ButtonTemplate;
    }
  }

  if (figmaNode.type === 'FRAME') {
    if (figmaNode.layoutMode === 'HORIZONTAL' || figmaNode.layoutMode === 'VERTICAL') {
      return LayoutTemplate;
    }
    if (figmaNode.children?.length > 3) {
      return CardTemplate;
    }
  }

  return null;
}

// Generate code from Figma selection
export function generateCodeFromFigma(figmaSelection: any): string {
  const template = matchTemplate(figmaSelection);

  if (template) {
    return template.generateCode(figmaSelection);
  }

  // Default fallback
  return `<div className="p-4">
  {/* Generated from Figma: ${figmaSelection.name || 'Untitled'} */}
  {/* Add your content here */}
</div>`;
}

// Export for MCP integration
export default {
  ComponentTemplates,
  matchTemplate,
  generateCodeFromFigma
};