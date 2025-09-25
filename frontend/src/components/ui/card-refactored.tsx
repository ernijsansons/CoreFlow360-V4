import * as React from "react"
import { cn } from "@/lib/utils"

/**
 * Card components refactored to use design tokens
 * Uses semantic tokens for consistent spacing, colors, and typography
 */
const Card = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      "rounded-card bg-surface text-primary shadow-card border border-muted",
      className
    )}
    {...props}
  />
))
Card.displayName = "Card"

const CardHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex flex-col space-y-component-xs p-component-lg", className)}
    {...props}
  />
))
CardHeader.displayName = "CardHeader"

const CardTitle = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
  <h3
    ref={ref}
    className={cn(
      "heading-3 text-primary",
      className
    )}
    {...props}
  />
))
CardTitle.displayName = "CardTitle"

const CardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn("body-small text-secondary", className)}
    {...props}
  />
))
CardDescription.displayName = "CardDescription"

const CardContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div 
    ref={ref} 
    className={cn("p-component-lg pt-0", className)} 
    {...props} 
  />
))
CardContent.displayName = "CardContent"

const CardFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center p-component-lg pt-0 gap-component-sm", className)}
    {...props}
  />
))
CardFooter.displayName = "CardFooter"

export { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent }

/**
 * Usage Examples with Design Tokens:
 * 
 * // Basic card with semantic tokens
 * <Card>
 *   <CardHeader>
 *     <CardTitle>Settings</CardTitle>
 *     <CardDescription>Manage your account preferences</CardDescription>
 *   </CardHeader>
 *   <CardContent>
 *     {/* Content uses consistent spacing */}
 *   </CardContent>
 *   <CardFooter>
 *     <Button>Save</Button>
 *     <Button variant="ghost">Cancel</Button>
 *   </CardFooter>
 * </Card>
 */