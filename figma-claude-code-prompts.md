# Figma Dev Mode MCP Prompts for Claude Code

Copy and paste these prompts into Claude Code when working with your Figma designs.

## Initial Setup & Testing

### Test Connection:
```
Check if the Figma Dev Mode MCP server is working. List all available tools and explain what each one does.
```

### Verify Dev Mode:
```
I have Figma Desktop open with Dev Mode enabled. Can you test the connection and tell me what tools are available?
```

## Basic Code Generation

### From Selection:
```
I've selected a component in Figma. Please generate a React component with TypeScript and Tailwind CSS from my current selection.
```

### From Figma Link:
```
Generate code for this Figma design: [PASTE_FIGMA_LINK_HERE]
Use React with TypeScript and styled-components.
```

### Multiple Frameworks:
```
Create implementations of my Figma selection in:
1. React with Tailwind
2. Vue 3 with Composition API
3. Plain HTML/CSS
4. Next.js with CSS Modules
```

## Design System Integration

### Extract Variables:
```
Extract all design tokens (colors, typography, spacing) from my current Figma file and create:
1. CSS variables file
2. Tailwind config extension
3. TypeScript theme object
```

### Use Existing Components:
```
Generate code for my Figma selection, but integrate with my existing component library:
- Use Button from '@/components/ui/Button'
- Use Card from '@/components/ui/Card'  
- Apply theme from '@/styles/theme'
```

## Advanced Code Generation

### Full Page with Responsiveness:
```
Generate a complete responsive page from my Figma selection:
- Mobile-first approach
- Use CSS Grid for layout
- Include all interactive states
- Add proper semantic HTML
- Ensure WCAG AA compliance
```

### Component with Variants:
```
I've selected a Figma component with multiple variants. Generate:
- A React component that supports all variants
- TypeScript props interface
- Storybook stories for each variant
- Unit tests with React Testing Library
```

### Animation & Interactions:
```
Generate code for my Figma selection with:
- Framer Motion animations for transitions
- Hover and focus states
- Loading and error states
- Smooth scrolling behavior
```

## Specialized Outputs

### Design System Documentation:
```
Create a complete design system documentation from my Figma file:
- Component inventory with code examples
- Color palette with accessibility notes
- Typography scale
- Spacing system
- Usage guidelines
```

### Form Generation:
```
Convert my Figma form design into a working form with:
- React Hook Form integration
- Zod validation schema
- Error handling and display
- Accessibility features
- Submit handling
```

### Data Visualization:
```
Transform my Figma chart/graph design into:
- Interactive Recharts component
- Responsive sizing
- Real data integration setup
- Proper animations
- Accessibility features
```

## Optimization Requests

### Performance Optimization:
```
Generate code for my Figma selection optimized for performance:
- Lazy load images
- Use CSS containment
- Minimize re-renders
- Add loading states
- Implement virtual scrolling if needed
```

### SEO Optimization:
```
Create SEO-optimized code from my Figma design:
- Semantic HTML structure
- Schema.org markup
- Meta tags setup
- Open Graph tags
- Optimized image loading
```

## Integration Patterns

### API Integration:
```
Generate code for my Figma design with API integration:
- Setup data fetching with React Query
- Add loading and error states
- Type the API response
- Handle edge cases
- Add retry logic
```

### State Management:
```
Convert my Figma design to React with state management:
- Use Zustand for global state
- Local state with useState
- Form state with React Hook Form
- Server state with React Query
```

## Workflow Enhancement

### Quick Component:
```
#get_code - Quick React component with Tailwind
```

### With Preview:
```
Generate code for my selection and also show me #get_image preview of what we're building
```

### Variables Check:
```
First use #get_variables to show me all design tokens, then generate code that uses these tokens consistently
```

## Debugging & Refinement

### Fix Spacing Issues:
```
The generated code doesn't match the Figma spacing. Can you check the design again and fix the margins and padding?
```

### Add Missing States:
```
Add hover, active, and disabled states to the generated component based on the Figma design system
```

### Improve Accessibility:
```
Review the generated code and enhance it with:
- ARIA labels
- Keyboard navigation
- Screen reader support
- Focus indicators
- Color contrast fixes
```

## Project-Specific Templates

### Landing Page Section:
```
Convert my Figma hero section to Next.js code:
- Use App Router
- Add scroll animations with Framer Motion
- Optimize images with next/image
- Make it fully responsive
- Add CMS integration points
```

### Dashboard Component:
```
Transform my Figma dashboard widget into:
- React component with TypeScript
- Real-time data updates
- Chart.js integration
- Export functionality
- Mobile responsive design
```

### E-commerce Card:
```
Generate a product card component from Figma:
- Add to cart functionality
- Wishlist toggle
- Quick view modal
- Price formatting
- Stock status display
```

## Tips for Best Results:

1. **Be Specific**: Mention the exact framework, styling approach, and features you need
2. **Layer Names Matter**: Well-named Figma layers result in better code
3. **Select Precisely**: Select only the frame/component you want to convert
4. **Iterate**: Start simple, then add complexity with follow-up prompts
5. **Verify Output**: Always test the generated code and refine as needed

## Common Issues & Solutions:

**"No tools available"**
→ Make sure Figma Desktop has "Enable local MCP Server" checked and Dev Mode is ON

**"Cannot read selection"**
→ Select a frame or component in Figma before running the prompt

**"Code doesn't match design"**
→ Ask Claude to check specific properties: "Verify the padding and colors match the Figma design"
