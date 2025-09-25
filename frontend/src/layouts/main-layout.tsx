import * as React from 'react'
import { useUIStore } from '@/stores'
import { EntitySwitcher } from '@/components/entity-switcher'
import { Sidebar } from '@/components/sidebar'
import { Header } from '@/components/header'
import { Breadcrumbs } from '@/components/breadcrumbs'
import { cn } from '@/lib/utils'

interface MainLayoutProps {
  children: React.ReactNode
}

export function MainLayout({ children }: MainLayoutProps) {
  const { sidebarOpen } = useUIStore()

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <Header />

      <div className="flex">
        {/* Sidebar */}
        <Sidebar />

        {/* Main Content */}
        <main
          className={cn(
            "flex-1 transition-all duration-200 ease-in-out",
            sidebarOpen ? "lg:ml-64" : "lg:ml-16"
          )}
        >
          <div className="p-6">
            {/* Breadcrumbs */}
            <Breadcrumbs className="mb-6" />

            {/* Page Content */}
            <div className="space-y-6">
              {children}
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}