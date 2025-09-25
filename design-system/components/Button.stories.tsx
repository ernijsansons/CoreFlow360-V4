import type { Meta, StoryObj } from '@storybook/react';
import { Button } from './primitives';
import { Save, ArrowRight, Download, Plus } from 'lucide-react';

const meta: Meta<typeof Button> = {
  title: 'Primitives/Button',
  component: Button,
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component: 'The Button component - not just clickable, but irresistible. Every button is a promise of action.',
      },
    },
  },
  tags: ['autodocs'],
  argTypes: {
    variant: {
      control: { type: 'select' },
      options: ['primary', 'secondary', 'ghost'],
      description: 'Visual style variant',
    },
    size: {
      control: { type: 'select' },
      options: ['small', 'default'],
      description: 'Size of the button',
    },
    loading: {
      control: { type: 'boolean' },
      description: 'Show loading state',
    },
    disabled: {
      control: { type: 'boolean' },
      description: 'Disable the button',
    },
    shortcut: {
      control: { type: 'text' },
      description: 'Keyboard shortcut to display',
    },
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

// Primary variant
export const Primary: Story = {
  args: {
    children: 'Save Changes',
    variant: 'primary',
    size: 'default',
  },
};

// Secondary variant
export const Secondary: Story = {
  args: {
    children: 'Cancel',
    variant: 'secondary',
    size: 'default',
  },
};

// Ghost variant
export const Ghost: Story = {
  args: {
    children: 'Learn More',
    variant: 'ghost',
    size: 'default',
  },
};

// With icon
export const WithIcon: Story = {
  args: {
    children: 'Save',
    variant: 'primary',
    icon: <Save className="w-4 h-4" />,
  },
};

// With shortcut
export const WithShortcut: Story = {
  args: {
    children: 'Save',
    variant: 'primary',
    shortcut: '⌘S',
    icon: <Save className="w-4 h-4" />,
  },
};

// Loading state
export const Loading: Story = {
  args: {
    children: 'Processing',
    variant: 'primary',
    loading: true,
  },
};

// Disabled state
export const Disabled: Story = {
  args: {
    children: 'Unavailable',
    variant: 'primary',
    disabled: true,
  },
};

// Small size
export const Small: Story = {
  args: {
    children: 'Small Button',
    variant: 'secondary',
    size: 'small',
  },
};

// Button group
export const ButtonGroup: Story = {
  render: () => (
    <div className="flex gap-3">
      <Button variant="primary" icon={<Save className="w-4 h-4" />}>
        Save
      </Button>
      <Button variant="secondary">
        Save as Draft
      </Button>
      <Button variant="ghost">
        Cancel
      </Button>
    </div>
  ),
};

// Interactive states
export const InteractiveStates: Story = {
  render: () => (
    <div className="grid grid-cols-3 gap-4">
      <div className="text-center">
        <Button variant="primary">Default</Button>
        <p className="text-xs mt-2 text-gray-500">Normal state</p>
      </div>
      <div className="text-center">
        <Button variant="primary" className="scale-[1.02]">
          Hover
        </Button>
        <p className="text-xs mt-2 text-gray-500">scale: 1.02</p>
      </div>
      <div className="text-center">
        <Button variant="primary" className="scale-[0.98]">
          Active
        </Button>
        <p className="text-xs mt-2 text-gray-500">scale: 0.98</p>
      </div>
    </div>
  ),
};

// Action buttons showcase
export const ActionButtons: Story = {
  render: () => (
    <div className="space-y-4">
      <div className="flex gap-3">
        <Button variant="primary" icon={<Plus className="w-4 h-4" />}>
          Create New
        </Button>
        <Button variant="primary" icon={<Download className="w-4 h-4" />}>
          Export
        </Button>
        <Button variant="primary" icon={<ArrowRight className="w-4 h-4" />}>
          Continue
        </Button>
      </div>
      <div className="flex gap-3">
        <Button variant="secondary" size="small">
          Edit
        </Button>
        <Button variant="secondary" size="small">
          Duplicate
        </Button>
        <Button variant="ghost" size="small">
          Delete
        </Button>
      </div>
    </div>
  ),
};

// Loading states comparison
export const LoadingStates: Story = {
  render: () => (
    <div className="space-y-4">
      <Button variant="primary" loading>
        Saving...
      </Button>
      <Button variant="secondary" loading>
        Processing...
      </Button>
      <Button variant="ghost" loading>
        Loading...
      </Button>
    </div>
  ),
};

// Responsive button
export const Responsive: Story = {
  render: () => (
    <div className="w-full max-w-md">
      <Button variant="primary" className="w-full">
        Full Width Button
      </Button>
    </div>
  ),
  parameters: {
    viewport: {
      defaultViewport: 'iphone14',
    },
  },
};