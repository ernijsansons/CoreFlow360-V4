import { createFileRoute } from '@tanstack/react-router'
import { PortfolioDashboard } from '@/modules/portfolio/PortfolioDashboard'

export const Route = createFileRoute('/dashboard/portfolio')({
  component: PortfolioDashboard,
})
