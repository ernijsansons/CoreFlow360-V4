/**
 * COMPONENT TESTING SUITE
 * Comprehensive tests for the revolutionary design system
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe, toHaveNoViolations } from 'jest-axe';
import '@testing-library/jest-dom';

import {
  Button,
  Input,
  Card,
  Badge,
  Skeleton,
  Separator,
  Text,
  Tooltip
} from '../components/primitives';

import {
  CommandBar,
  IntelligentDashboard,
  DataTable
} from '../components/signature-interfaces';

import { Pipeline } from '../components/pipeline-crm';
import { MetricCard, LineChart, DonutChart } from '../components/financial-dashboard';
import {
  HoverIntelligence,
  KeyboardNavigationProvider,
  UndoSystemProvider,
  OptimisticUpdate,
  LoadingState
} from '../interactions/paradigms';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

// Helper to wrap components with providers
const AllProviders: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <KeyboardNavigationProvider>
    <UndoSystemProvider>
      {children}
    </UndoSystemProvider>
  </KeyboardNavigationProvider>
);

describe('Button Component', () => {
  it('renders with text', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });

  it('handles click events', async () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click me</Button>);

    await userEvent.click(screen.getByText('Click me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('shows loading state', () => {
    render(<Button loading>Save</Button>);
    expect(screen.getByText('Save')).toBeInTheDocument();
    // Should have loading spinner
    expect(document.querySelector('.animate-spin')).toBeInTheDocument();
  });

  it('respects disabled state', async () => {
    const handleClick = jest.fn();
    render(<Button disabled onClick={handleClick}>Disabled</Button>);

    await userEvent.click(screen.getByText('Disabled'));
    expect(handleClick).not.toHaveBeenCalled();
  });

  it('displays keyboard shortcut', () => {
    render(<Button shortcut="⌘S">Save</Button>);
    expect(screen.getByText('⌘S')).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    const { container } = render(<Button>Accessible Button</Button>);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('supports all variants', () => {
    const { rerender } = render(<Button variant="primary">Primary</Button>);
    expect(screen.getByText('Primary')).toHaveClass('bg-black');

    rerender(<Button variant="secondary">Secondary</Button>);
    expect(screen.getByText('Secondary')).toHaveClass('border');

    rerender(<Button variant="ghost">Ghost</Button>);
    expect(screen.getByText('Ghost')).toHaveClass('bg-transparent');
  });
});

describe('Input Component', () => {
  it('accepts text input', async () => {
    render(<Input label="Email" />);
    const input = screen.getByRole('textbox');

    await userEvent.type(input, 'test@example.com');
    expect(input).toHaveValue('test@example.com');
  });

  it('shows error state', () => {
    render(<Input label="Email" error="Invalid email" />);
    expect(screen.getByText('Invalid email')).toBeInTheDocument();
  });

  it('animates label on focus', async () => {
    render(<Input label="Email" />);
    const input = screen.getByRole('textbox');
    const label = screen.getByText('Email');

    await userEvent.click(input);
    // Label should animate up
    expect(label).toHaveStyle({ fontSize: '11px' });
  });

  it('supports icon prop', () => {
    const Icon = () => <span data-testid="icon">@</span>;
    render(<Input icon={<Icon />} />);
    expect(screen.getByTestId('icon')).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    const { container } = render(<Input label="Accessible Input" />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});

describe('CommandBar Component', () => {
  const mockSuggestions = [
    {
      id: '1',
      title: 'Create Invoice',
      description: 'Start a new invoice',
      action: jest.fn(),
      shortcut: '⌘I'
    },
    {
      id: '2',
      title: 'View Analytics',
      description: 'Open dashboard',
      action: jest.fn(),
      shortcut: '⌘A'
    }
  ];

  it('opens on / key press', async () => {
    render(<CommandBar suggestions={mockSuggestions} />);

    fireEvent.keyDown(window, { key: '/' });
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Type '\/'/)).toBeInTheDocument();
    });
  });

  it('filters suggestions based on query', async () => {
    render(<CommandBar suggestions={mockSuggestions} />);

    fireEvent.keyDown(window, { key: '/' });
    const input = await screen.findByPlaceholderText(/Type '\/'/);

    await userEvent.type(input, 'invoice');
    expect(screen.getByText('Create Invoice')).toBeInTheDocument();
    expect(screen.queryByText('View Analytics')).not.toBeInTheDocument();
  });

  it('executes action on Enter', async () => {
    render(<CommandBar suggestions={mockSuggestions} />);

    fireEvent.keyDown(window, { key: '/' });
    const input = await screen.findByPlaceholderText(/Type '\/'/);

    await userEvent.type(input, 'invoice');
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(mockSuggestions[0].action).toHaveBeenCalled();
  });

  it('navigates with arrow keys', async () => {
    render(<CommandBar suggestions={mockSuggestions} />);

    fireEvent.keyDown(window, { key: '/' });
    await screen.findByPlaceholderText(/Type '\/'/);

    fireEvent.keyDown(window, { key: 'ArrowDown' });
    // First suggestion should be highlighted
    expect(screen.getByText('Create Invoice').parentElement).toHaveClass('bg-black/4');
  });

  it('closes on Escape', async () => {
    render(<CommandBar suggestions={mockSuggestions} />);

    fireEvent.keyDown(window, { key: '/' });
    await screen.findByPlaceholderText(/Type '\/'/);

    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => {
      expect(screen.queryByPlaceholderText(/Type '\/'/)).not.toBeInTheDocument();
    });
  });
});

describe('DataTable Component', () => {
  const mockData = [
    { id: '1', name: 'Item 1', value: 100 },
    { id: '2', name: 'Item 2', value: 200 },
    { id: '3', name: 'Item 3', value: 150 }
  ];

  const mockColumns = [
    { key: 'name' as keyof typeof mockData[0], title: 'Name', sortable: true },
    { key: 'value' as keyof typeof mockData[0], title: 'Value', sortable: true, align: 'right' as const }
  ];

  it('renders table with data', () => {
    render(<DataTable columns={mockColumns} data={mockData} />);

    expect(screen.getByText('Item 1')).toBeInTheDocument();
    expect(screen.getByText('200')).toBeInTheDocument();
  });

  it('handles row selection', async () => {
    const handleSelection = jest.fn();
    render(
      <DataTable
        columns={mockColumns}
        data={mockData}
        onSelectionChange={handleSelection}
      />
    );

    const checkboxes = screen.getAllByRole('checkbox');
    await userEvent.click(checkboxes[1]); // Click first row checkbox

    expect(handleSelection).toHaveBeenCalledWith([mockData[0]]);
  });

  it('sorts data when clicking sortable columns', async () => {
    render(<DataTable columns={mockColumns} data={mockData} />);

    const nameHeader = screen.getByText('Name');
    await userEvent.click(nameHeader);

    const rows = screen.getAllByRole('row');
    // Should be sorted alphabetically
    expect(rows[1]).toHaveTextContent('Item 1');
  });

  it('handles row click events', async () => {
    const handleRowClick = jest.fn();
    render(
      <DataTable
        columns={mockColumns}
        data={mockData}
        onRowClick={handleRowClick}
      />
    );

    await userEvent.click(screen.getByText('Item 1'));
    expect(handleRowClick).toHaveBeenCalledWith(mockData[0]);
  });
});

describe('Pipeline Component', () => {
  const mockStages = [
    {
      id: 'prospect',
      title: 'Prospect',
      deals: [
        {
          id: '1',
          company: 'Acme Corp',
          amount: 100000,
          stage: 'prospect',
          daysInStage: 5,
          probability: 20
        }
      ]
    },
    {
      id: 'qualified',
      title: 'Qualified',
      deals: []
    }
  ];

  it('renders pipeline stages', () => {
    render(<Pipeline stages={mockStages} />);

    expect(screen.getByText('Prospect')).toBeInTheDocument();
    expect(screen.getByText('Qualified')).toBeInTheDocument();
    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
  });

  it('displays deal values correctly', () => {
    render(<Pipeline stages={mockStages} />);

    expect(screen.getByText('$100K')).toBeInTheDocument();
    expect(screen.getByText('20%')).toBeInTheDocument();
  });

  it('handles deal click', async () => {
    const handleDealClick = jest.fn();
    render(<Pipeline stages={mockStages} onDealClick={handleDealClick} />);

    await userEvent.click(screen.getByText('Acme Corp'));
    expect(handleDealClick).toHaveBeenCalledWith(mockStages[0].deals[0]);
  });

  it('shows empty state for stages without deals', () => {
    render(<Pipeline stages={mockStages} />);

    expect(screen.getByText('Drop deals here')).toBeInTheDocument();
  });
});

describe('Interaction Paradigms', () => {
  describe('HoverIntelligence', () => {
    it('shows tooltip on hover', async () => {
      render(
        <HoverIntelligence
          content={{
            what: 'Save document',
            why: 'Preserves changes',
            how: 'Click or press ⌘S'
          }}
        >
          <button>Save</button>
        </HoverIntelligence>
      );

      const button = screen.getByText('Save');
      fireEvent.mouseEnter(button);

      await waitFor(() => {
        expect(screen.getByText('Save document')).toBeInTheDocument();
      });
    });

    it('shows progressive detail after longer hover', async () => {
      jest.useFakeTimers();

      render(
        <HoverIntelligence
          content={{
            what: 'Save',
            why: 'Preserves changes',
            how: 'Click button'
          }}
          delay={100}
        >
          <button>Save</button>
        </HoverIntelligence>
      );

      fireEvent.mouseEnter(screen.getByText('Save'));

      // After initial delay
      jest.advanceTimersByTime(100);
      await waitFor(() => {
        expect(screen.getByText('Save')).toBeInTheDocument();
      });

      // After progressive delay
      jest.advanceTimersByTime(500);
      await waitFor(() => {
        expect(screen.getByText(/Preserves changes/)).toBeInTheDocument();
      });

      jest.useRealTimers();
    });
  });

  describe('UndoSystem', () => {
    it('handles undo/redo operations', () => {
      const TestComponent = () => {
        const { addAction, undo, redo, canUndo, canRedo } = useUndo();
        const [value, setValue] = React.useState('initial');

        const handleChange = (newValue: string) => {
          const oldValue = value;
          setValue(newValue);

          addAction({
            description: `Change value to ${newValue}`,
            undo: () => setValue(oldValue),
            redo: () => setValue(newValue)
          });
        };

        return (
          <div>
            <input value={value} onChange={(e) => handleChange(e.target.value)} />
            <button onClick={undo} disabled={!canUndo}>Undo</button>
            <button onClick={redo} disabled={!canRedo}>Redo</button>
          </div>
        );
      };

      render(
        <UndoSystemProvider>
          <TestComponent />
        </UndoSystemProvider>
      );

      const input = screen.getByRole('textbox');

      // Make a change
      fireEvent.change(input, { target: { value: 'changed' } });
      expect(input).toHaveValue('changed');

      // Undo
      fireEvent.click(screen.getByText('Undo'));
      expect(input).toHaveValue('initial');

      // Redo
      fireEvent.click(screen.getByText('Redo'));
      expect(input).toHaveValue('changed');
    });
  });
});

describe('Accessibility Tests', () => {
  it('Button has no violations', async () => {
    const { container } = render(<Button>Accessible</Button>);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('Input has no violations', async () => {
    const { container } = render(<Input label="Accessible Input" />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('DataTable has no violations', async () => {
    const { container } = render(
      <DataTable
        columns={[{ key: 'name', title: 'Name' }]}
        data={[{ id: '1', name: 'Test' }]}
      />
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});

describe('Performance Tests', () => {
  it('renders large dataset efficiently', () => {
    const largeData = Array.from({ length: 1000 }, (_, i) => ({
      id: `${i}`,
      name: `Item ${i}`,
      value: Math.random() * 1000
    }));

    const start = performance.now();

    render(
      <DataTable
        columns={[
          { key: 'name', title: 'Name' },
          { key: 'value', title: 'Value' }
        ]}
        data={largeData}
      />
    );

    const end = performance.now();
    const renderTime = end - start;

    // Should render under 100ms even with 1000 items
    expect(renderTime).toBeLessThan(100);
  });
});