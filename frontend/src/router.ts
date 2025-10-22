import { createRouter } from '@tanstack/react-router'
import { routeTree } from './routeTree.gen'

export const router = createRouter({
  routeTree,
  // Preload on intent (hover/focus) for better UX
  defaultPreload: 'intent',
  defaultPreloadStaleTime: 10_000, // Cache preloaded routes for 10s
  context: undefined!,
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
