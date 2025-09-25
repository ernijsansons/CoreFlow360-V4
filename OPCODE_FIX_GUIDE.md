# 🔧 OpCode MCP Fix Guide - Resolving Connection Issues

## 🚨 **Problem Identified**
The MCP server configuration is causing "Invalid API key" and connection errors in OpCode. This is likely due to:
1. Too many MCP servers configured at once
2. Conflicting server configurations
3. Missing dependencies for some servers

## ✅ **Solution: Minimal Working Configuration**

### **Step 1: Use Simplified Configuration**
Replace your `OpCode MCP - CoreFlow360.json` with this minimal version:

```json
{
  "mcpServers": {
    "coreflow-filesystem": {
      "type": "stdio",
      "command": "mcp-filesystem-server",
      "args": ["C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4"],
      "env": {
        "MAX_FILE_SIZE": "10485760"
      }
    },
    "coreflow-database": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@executeautomation/database-server", "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4\\db.sqlite"]
    },
    "coreflow-shell": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-shell-server"],
      "env": {
        "ALLOW_COMMANDS": "ls,cat,pwd,grep,python,node,npm,git"
      }
    }
  }
}
```

### **Step 2: Install Required Dependencies**
```bash
# Install filesystem server
npm install -g mcp-filesystem-server

# Install database server
npm install -g @executeautomation/database-server

# Install shell server
pip install mcp-shell-server
```

### **Step 3: Restart OpCode Desktop**
1. Close OpCode Desktop completely
2. Reopen OpCode Desktop
3. Go to Settings → MCP Servers
4. Import the new configuration file
5. Wait for all 3 servers to show "Connected" status

### **Step 4: Test Basic Functionality**
Try these simple commands in Claude:
- "List files in my project directory"
- "Show me the contents of package.json"
- "Check git status"

## 🔍 **Troubleshooting Steps**

### **If Still Getting Errors:**

#### **Option 1: Start with Just Filesystem**
```json
{
  "mcpServers": {
    "coreflow-filesystem": {
      "type": "stdio",
      "command": "mcp-filesystem-server",
      "args": ["C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4"]
    }
  }
}
```

#### **Option 2: Check Dependencies**
```bash
# Verify Node.js
node --version

# Verify Python
python --version

# Verify npm packages
npm list -g mcp-filesystem-server
npm list -g @executeautomation/database-server

# Verify Python packages
pip list | grep mcp
```

#### **Option 3: Test Individual Servers**
```bash
# Test filesystem server
mcp-filesystem-server "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4"

# Test database server
npx @executeautomation/database-server "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4\\db.sqlite"

# Test shell server
uvx mcp-shell-server
```

## 🚀 **Gradual Expansion**

Once the basic configuration works, you can gradually add more servers:

### **Phase 1: Add Database Server**
```json
{
  "mcpServers": {
    "coreflow-filesystem": {
      "type": "stdio",
      "command": "mcp-filesystem-server",
      "args": ["C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4"]
    },
    "coreflow-database": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@executeautomation/database-server", "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4\\db.sqlite"]
    }
  }
}
```

### **Phase 2: Add Shell Server**
```json
{
  "mcpServers": {
    "coreflow-filesystem": {
      "type": "stdio",
      "command": "mcp-filesystem-server",
      "args": ["C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4"]
    },
    "coreflow-database": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@executeautomation/database-server", "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4\\db.sqlite"]
    },
    "coreflow-shell": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-shell-server"],
      "env": {
        "ALLOW_COMMANDS": "ls,cat,pwd,grep,python,node,npm,git"
      }
    }
  }
}
```

## 🎯 **Expected Results**

After applying the fix, you should see:
- ✅ All MCP servers show "Connected" status
- ✅ No "Invalid API key" errors
- ✅ Claude can access your project files
- ✅ Basic commands work without errors

## 📞 **If Problems Persist**

1. **Check OpCode Desktop Logs**
   - Go to Help → Show Logs
   - Look for MCP-related error messages

2. **Reset OpCode Configuration**
   - Delete the MCP configuration file
   - Restart OpCode Desktop
   - Re-import the configuration

3. **Verify File Paths**
   - Ensure all paths in the config are correct
   - Check that the project directory exists
   - Verify database file exists

4. **Check System Requirements**
   - Windows 10/11
   - Node.js 16+ installed
   - Python 3.8+ installed
   - OpCode Desktop latest version

## 🔄 **Rollback Plan**

If nothing works, you can temporarily disable MCP servers:
1. Remove the MCP configuration file
2. Restart OpCode Desktop
3. Use OpCode without MCP servers
4. Gradually re-enable servers one by one

**The key is to start simple and build up gradually rather than configuring everything at once.**
