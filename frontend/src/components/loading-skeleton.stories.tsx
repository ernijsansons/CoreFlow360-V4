import type { Meta, StoryObj } from '@storybook/react'
import { LoadingSkeleton, PageSkeleton, TableSkeleton, FormSkeleton } from './loading-skeleton'

const meta = {
  title: 'Components/LoadingSkeleton',
  component: LoadingSkeleton,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
  argTypes: {
    type: {
      control: 'select',
      options: ['text', 'card', 'avatar', 'button', 'table', 'list'],
    },
    count: {
      control: { type: 'number', min: 1, max: 10 },
    },
  },
} satisfies Meta<typeof LoadingSkeleton>

export default meta
type Story = StoryObj<typeof meta>

export const Text: Story = {
  args: {
    type: 'text',
    count: 1,
  },
}

export const Card: Story = {
  args: {
    type: 'card',
    count: 1,
  },
}

export const Avatar: Story = {
  args: {
    type: 'avatar',
    count: 1,
  },
}

export const Button: Story = {
  args: {
    type: 'button',
    count: 1,
  },
}

export const Table: Story = {
  args: {
    type: 'table',
    count: 5,
  },
}

export const List: Story = {
  args: {
    type: 'list',
    count: 3,
  },
}

export const MultiplCards: Story = {
  args: {
    type: 'card',
    count: 3,
  },
}

export const Page: Story = {
  render: () => <PageSkeleton />,
}

export const TableWithRows: Story = {
  render: () => <TableSkeleton rows={8} />,
}

export const Form: Story = {
  render: () => <FormSkeleton />,
}