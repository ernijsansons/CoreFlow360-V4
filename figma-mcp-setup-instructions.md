# Setting Up Figma Dev Mode MCP in Claude Code

## Overview
Since you have a paid Figma account with Dev Mode, you can use the official **Figma Dev Mode MCP Server** - the most powerful integration that provides:
- Direct code generation from designs (React, Tailwind, etc.)
- Access to design tokens, variables, and components
- Real-time connection to your Figma files
- Advanced design-to-code capabilities

## Step 1: Enable MCP Server in Figma Desktop

1. Open **Figma Desktop App** (required - not the web version)
2. Click the Figma menu (top-left corner)
3. Go to **Preferences**
4. Check **"Enable local MCP Server"**
5. You should see a confirmation that the server is running
6. The server runs at `http://127.0.0.1:3845/mcp`

## Step 2: Configure Claude Code

Since you already have `figma-dev-mode-mcp-server` configured and it shows as connected, we just need to ensure it's properly set up.

Your current configuration in `C:\Users\ernij\.claude.json` should look like this:

```json
{
  "mcpServers": {
    "figma-dev-mode-mcp-server": {
      "type": "http",
      "url": "http://127.0.0.1:3845/mcp"
    }
  }
}
```

## Step 3: Open a Figma File in Dev Mode

1. Open any Figma design file in the desktop app
2. Click the **"<> Dev Mode"** toggle in the top-right corner
3. Dev Mode should now be active (interface changes to developer view)

## Step 4: Test the Connection

In Claude Code, try these prompts:

### Basic Test:
```
Check if Figma Dev Mode MCP is working and list available tools
```

### Get Code from Selection:
1. Select a frame or component in Figma
2. In Claude Code:
```
Generate React code for my current Figma selection
```

### Get Code from Link:
```
Generate code for this Figma frame: [paste Figma link here]
```

## Available Tools

The Dev Mode MCP Server provides these tools:

- **`#get_code`** - Generate code from Figma selection/link
- **`#get_image`** - Get screenshot of design
- **`#get_variables`** - Get design tokens and variables

## Example Prompts for Claude Code

### Generate Component Code:
```
Get the code for my current Figma selection and create a React component with Tailwind CSS
```

### Build Full Page:
```
Generate a complete React page from this Figma design: [link]. 
Include all components, use my design system variables, and make it responsive.
```

### Extract Design System:
```
Extract all color variables and typography styles from my current Figma file and create a CSS variables file
```

### Convert to Different Framework:
```
Convert my Figma selection to:
- Vue component with Tailwind
- Next.js page with CSS modules
- Plain HTML/CSS
```

### Advanced Integration:
```
Generate code for my Figma selection, but:
- Use my existing Button component from components/ui/Button
- Apply the color scheme from my design tokens
- Make it fully accessible with ARIA labels
- Add hover states and transitions
```

## Troubleshooting

If tools aren't showing up:

1. **Restart Figma Desktop App**
   - Make sure "Enable local MCP Server" is checked
   - Wait for confirmation message

2. **Restart Claude Code**
   - Run: `claude mcp list`
   - Should show `figma-dev-mode-mcp-server: ✓ Connected`

3. **Verify Dev Mode is Active**
   - The Dev Mode toggle should be ON in your Figma file
   - You need a Dev or Full seat on Professional/Organization/Enterprise plan

4. **Try Direct HTTP Test**:
   ```
   Test the Figma MCP server by making a request to http://127.0.0.1:3845/mcp
   ```

## Pro Tips

1. **Select Before Generating**: Always select the specific frame/component you want to convert in Figma before asking for code

2. **Use Specific Prompts**: Be clear about what framework/styling you want:
   - "Generate React component with Tailwind"
   - "Create Vue component with Vuetify"
   - "Build vanilla HTML/CSS"

3. **Leverage Design Tokens**: If your Figma file uses variables/tokens, ask Claude to use them:
   ```
   Generate code using the design system variables from my Figma file
   ```

4. **Iterate on Output**: You can refine the generated code:
   ```
   Update the component to use CSS Grid instead of Flexbox
   ```

## Best Practices

1. **Organize Your Figma File**:
   - Use meaningful layer names
   - Group related elements
   - Apply Auto Layout where possible
   - Use components and variants

2. **Design System Integration**:
   - Define variables in Figma for colors, spacing, typography
   - Use consistent naming conventions
   - These will be reflected in generated code

3. **Code Quality**:
   - Review generated code before using
   - Ask Claude to add TypeScript types if needed
   - Request specific accessibility features

Your Dev Mode MCP is already connected - now just make sure Figma Desktop has the MCP server enabled and you have a file open in Dev Mode!
