// UI Component Index - Centralized export
export { Button, buttonVariants, type ButtonProps } from './button-refactored'
export { Input } from './input-refactored'
export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './card-refactored'
export { Label } from './label'
export { Badge } from './badge-refactored'
export { Alert, AlertTitle, AlertDescription } from './alert'
export { Tabs, TabsList, TabsTrigger, TabsContent } from './tabs'

// Dropdown Menu components (from Radix UI)
export * as DropdownMenu from '@radix-ui/react-dropdown-menu'

// Create named exports for common dropdown components
export {
  Root as DropdownMenuRoot,
  Trigger as DropdownMenuTrigger,
  Content as DropdownMenuContent,
  Item as DropdownMenuItem,
  Label as DropdownMenuLabel,
  Separator as DropdownMenuSeparator,
  Group as DropdownMenuGroup,
} from '@radix-ui/react-dropdown-menu'
