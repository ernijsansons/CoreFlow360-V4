import { render } from '@testing-library/react'
import { LoadingSkeleton, PageSkeleton, TableSkeleton, FormSkeleton } from '../loading-skeleton'

describe('LoadingSkeleton', () => {
  it('renders text skeleton by default', () => {
    const { container } = render(<LoadingSkeleton />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('renders multiple skeletons based on count', () => {
    const { container } = render(<LoadingSkeleton count={3} />)
    const skeletons = container.querySelectorAll('.mb-4')
    expect(skeletons).toHaveLength(2) // count - 1 because last one doesn't have mb-4
  })

  it('renders different skeleton types', () => {
    const types = ['text', 'card', 'avatar', 'button', 'table', 'list'] as const

    types.forEach(type => {
      const { container } = render(<LoadingSkeleton type={type} />)
      expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
    })
  })

  it('applies custom className', () => {
    const { container } = render(<LoadingSkeleton className="custom-class" />)
    expect(container.querySelector('.custom-class')).toBeInTheDocument()
  })
})

describe('PageSkeleton', () => {
  it('renders page skeleton with grid layout', () => {
    const { container } = render(<PageSkeleton />)
    expect(container.querySelector('.container')).toBeInTheDocument()
    expect(container.querySelector('.grid')).toBeInTheDocument()
  })
})

describe('TableSkeleton', () => {
  it('renders table skeleton with default rows', () => {
    const { container } = render(<TableSkeleton />)
    expect(container.querySelector('.rounded-lg.border')).toBeInTheDocument()
  })

  it('renders table skeleton with custom rows', () => {
    const { container } = render(<TableSkeleton rows={10} />)
    expect(container.querySelector('.rounded-lg.border')).toBeInTheDocument()
  })
})

describe('FormSkeleton', () => {
  it('renders form skeleton', () => {
    const { container } = render(<FormSkeleton />)
    expect(container.querySelector('.space-y-4')).toBeInTheDocument()
  })
})