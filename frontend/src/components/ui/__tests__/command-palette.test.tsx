/**
 * Command Palette Test Suite
 * Tests for keyboard shortcuts, search, navigation, and accessibility
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'
import { BrowserRouter } from 'react-router-dom'
import { CommandPalette, useCommandPalette } from '../command-palette'

// Mock TanStack Router
vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => vi.fn()
}))

// Test wrapper with router
const TestWrapper = ({ children }: { children: React.ReactNode }) => (
  <BrowserRouter>{children}</BrowserRouter>
)

describe('CommandPalette', () => {
  const mockBusinesses = [
    { id: '1', name: 'Test SaaS', type: 'SaaS', revenue: '$100K', status: 'active' as const },
    { id: '2', name: 'Test Store', type: 'E-commerce', revenue: '$50K', status: 'active' as const }
  ]

  const mockRecentItems = [
    {
      id: 'recent-1',
      title: 'Recent Invoice',
      description: 'INV-001',
      icon: () => <span>📄</span>,
      action: vi.fn(),
      category: 'recent' as const
    }
  ]

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Keyboard Shortcuts', () => {
    it('should open with Cmd+K on Mac', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Simulate Cmd+K
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/Type a command or search/i)).toBeInTheDocument()
      })
    })

    it('should open with Ctrl+K on Windows', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Simulate Ctrl+K
      fireEvent.keyDown(document, { key: 'k', ctrlKey: true })

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/Type a command or search/i)).toBeInTheDocument()
      })
    })

    it('should close with Escape key', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/Type a command or search/i)).toBeInTheDocument()
      })

      // Close with Escape
      fireEvent.keyDown(document, { key: 'Escape' })

      await waitFor(() => {
        expect(screen.queryByPlaceholderText(/Type a command or search/i)).not.toBeInTheDocument()
      })
    })

    it('should support forward slash as alternative shortcut', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Simulate forward slash
      fireEvent.keyDown(document, { key: '/' })

      await waitFor(() => {
        expect(screen.getByPlaceholderText(/Type a command or search/i)).toBeInTheDocument()
      })
    })
  })

  describe('Search Functionality', () => {
    it('should filter items based on search query', async () => {
      render(
        <TestWrapper>
          <CommandPalette businesses={mockBusinesses} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Search for "dashboard"
      await userEvent.type(searchInput, 'dashboard')

      await waitFor(() => {
        expect(screen.getByText('Dashboard')).toBeInTheDocument()
        expect(screen.queryByText('Test SaaS')).not.toBeInTheDocument()
      })
    })

    it('should support fuzzy search', async () => {
      render(
        <TestWrapper>
          <CommandPalette businesses={mockBusinesses} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Fuzzy search
      await userEvent.type(searchInput, 'fnce')

      await waitFor(() => {
        expect(screen.getByText('Finance & Accounting')).toBeInTheDocument()
      })
    })

    it('should show empty state when no results', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Search for non-existent item
      await userEvent.type(searchInput, 'xyz123456')

      await waitFor(() => {
        expect(screen.getByText('No results found')).toBeInTheDocument()
      })
    })

    it('should search across item keywords', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Search by keyword
      await userEvent.type(searchInput, 'money')

      await waitFor(() => {
        expect(screen.getByText('Finance & Accounting')).toBeInTheDocument()
      })
    })
  })

  describe('Navigation', () => {
    it('should navigate with arrow keys', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await screen.findByPlaceholderText(/Type a command or search/i)

      // Navigate down
      fireEvent.keyDown(document, { key: 'ArrowDown' })

      // Check if first item is selected (implementation dependent)
      const firstItem = screen.getByText('Dashboard').closest('[cmdk-item]')
      expect(firstItem).toHaveAttribute('aria-selected')
    })

    it('should execute action on Enter key', async () => {
      const mockAction = vi.fn()
      const customItems = [
        {
          id: 'test-1',
          title: 'Test Action',
          icon: () => <span>✓</span>,
          action: mockAction,
          category: 'actions' as const
        }
      ]

      render(
        <TestWrapper>
          <CommandPalette recentItems={customItems} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Search for test action
      await userEvent.type(searchInput, 'Test Action')

      // Select with Enter
      fireEvent.keyDown(searchInput, { key: 'Enter' })

      await waitFor(() => {
        expect(mockAction).toHaveBeenCalled()
      })
    })

    it('should close after selecting an item', async () => {
      const mockClose = vi.fn()

      render(
        <TestWrapper>
          <CommandPalette onClose={mockClose} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Search and select
      await userEvent.type(searchInput, 'Dashboard')
      fireEvent.keyDown(searchInput, { key: 'Enter' })

      await waitFor(() => {
        expect(mockClose).toHaveBeenCalled()
      })
    })
  })

  describe('Categories', () => {
    it('should display all categories', async () => {
      render(
        <TestWrapper>
          <CommandPalette businesses={mockBusinesses} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await waitFor(() => {
        expect(screen.getByText('Navigation')).toBeInTheDocument()
        expect(screen.getByText('Actions')).toBeInTheDocument()
        expect(screen.getByText('AI Agents')).toBeInTheDocument()
        expect(screen.getByText('Switch Business')).toBeInTheDocument()
        expect(screen.getByText('Settings')).toBeInTheDocument()
      })
    })

    it('should display recent items when available', async () => {
      render(
        <TestWrapper>
          <CommandPalette recentItems={mockRecentItems} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await waitFor(() => {
        expect(screen.getByText('Recent')).toBeInTheDocument()
        expect(screen.getByText('Recent Invoice')).toBeInTheDocument()
      })
    })

    it('should display business switcher with correct data', async () => {
      render(
        <TestWrapper>
          <CommandPalette businesses={mockBusinesses} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await waitFor(() => {
        expect(screen.getByText('Test SaaS')).toBeInTheDocument()
        expect(screen.getByText('SaaS · $100K')).toBeInTheDocument()
        expect(screen.getByText('Test Store')).toBeInTheDocument()
        expect(screen.getByText('E-commerce · $50K')).toBeInTheDocument()
      })
    })
  })

  describe('Performance', () => {
    it('should render quickly with many items', async () => {
      const manyBusinesses = Array.from({ length: 100 }, (_, i) => ({
        id: `${i}`,
        name: `Business ${i}`,
        type: 'SaaS',
        revenue: `$${i}K`,
        status: 'active' as const
      }))

      const startTime = performance.now()

      render(
        <TestWrapper>
          <CommandPalette businesses={manyBusinesses} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await screen.findByPlaceholderText(/Type a command or search/i)

      const endTime = performance.now()
      const renderTime = endTime - startTime

      // Should render in less than 100ms
      expect(renderTime).toBeLessThan(100)
    })

    it('should search quickly through many items', async () => {
      const manyBusinesses = Array.from({ length: 100 }, (_, i) => ({
        id: `${i}`,
        name: `Business ${i}`,
        type: 'SaaS',
        revenue: `$${i}K`,
        status: 'active' as const
      }))

      render(
        <TestWrapper>
          <CommandPalette businesses={manyBusinesses} />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      const startTime = performance.now()

      // Perform search
      await userEvent.type(searchInput, 'Business 5')

      const endTime = performance.now()
      const searchTime = endTime - startTime

      // Search should complete in less than 100ms
      expect(searchTime).toBeLessThan(100)
    })
  })

  describe('Accessibility', () => {
    it('should have proper ARIA labels', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toHaveAttribute('aria-label', 'Command Palette')
      })
    })

    it('should support keyboard navigation', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Tab navigation
      await userEvent.tab()

      // Should be able to navigate with Tab
      expect(document.activeElement).not.toBe(searchInput)
    })

    it('should announce search results to screen readers', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      const searchInput = await screen.findByPlaceholderText(/Type a command or search/i)

      // Search
      await userEvent.type(searchInput, 'dashboard')

      // Check for aria-live regions or announcements
      const list = screen.getByRole('listbox')
      expect(list).toBeInTheDocument()
    })

    it('should have visible focus indicators', async () => {
      render(
        <TestWrapper>
          <CommandPalette />
        </TestWrapper>
      )

      // Open palette
      fireEvent.keyDown(document, { key: 'k', metaKey: true })

      await screen.findByPlaceholderText(/Type a command or search/i)

      const firstItem = screen.getByText('Dashboard').closest('[cmdk-item]')

      // Navigate to item
      fireEvent.keyDown(document, { key: 'ArrowDown' })

      // Check for focus styles (implementation dependent)
      expect(firstItem).toHaveAttribute('aria-selected')
    })
  })

  describe('useCommandPalette Hook', () => {
    it('should provide open/close/toggle functions', () => {
      const TestComponent = () => {
        const { isOpen, open, close, toggle } = useCommandPalette()

        return (
          <div>
            <span data-testid="status">{isOpen ? 'open' : 'closed'}</span>
            <button onClick={open}>Open</button>
            <button onClick={close}>Close</button>
            <button onClick={toggle}>Toggle</button>
          </div>
        )
      }

      const { getByTestId, getByText } = render(<TestComponent />)

      expect(getByTestId('status')).toHaveTextContent('closed')

      fireEvent.click(getByText('Open'))
      expect(getByTestId('status')).toHaveTextContent('open')

      fireEvent.click(getByText('Close'))
      expect(getByTestId('status')).toHaveTextContent('closed')

      fireEvent.click(getByText('Toggle'))
      expect(getByTestId('status')).toHaveTextContent('open')

      fireEvent.click(getByText('Toggle'))
      expect(getByTestId('status')).toHaveTextContent('closed')
    })
  })
})