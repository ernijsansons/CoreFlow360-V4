# 🚀 OpCode MCP Setup Guide for CoreFlow360

## 📋 **Complete Configuration for Claude Integration**

### **1. OpCode MCP Configuration File**
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
        "ALLOW_COMMANDS": "ls,cat,pwd,grep,python,node,npm,bun,git,docker,docker-compose,wrangler"
      }
    },
    "coreflow-cloudflare-proxy": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4\\cloudflare_proxy.py"],
      "env": {
        "PYTHONUNBUFFERED": "1",
        "MCP_LOG_LEVEL": "info"
      }
    },
    "coreflow-docker": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-docker-server"],
      "env": {
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "ALLOW_CONTAINERS": "coreflow360-*"
      }
    },
    "coreflow-git": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-git-server"],
      "env": {
        "GIT_REPO_PATH": "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4"
      }
    }
  }
}
```

### **2. Installation Commands**

#### **Install Required MCP Servers**
```bash
# Install filesystem server
npm install -g mcp-filesystem-server

# Install database server
npm install -g @executeautomation/database-server

# Install shell server
pip install mcp-shell-server

# Install Docker server
pip install mcp-docker-server

# Install Git server
pip install mcp-git-server
```

#### **Install Python Dependencies**
```bash
# Install MCP Python package
pip install mcp

# Install additional dependencies
pip install asyncio json logging
```

### **3. OpCode Desktop Configuration**

#### **Step 1: Open OpCode Desktop**
1. Launch OpCode Desktop application
2. Go to Settings → MCP Servers
3. Click "Import Configuration"
4. Select your `OpCode MCP - CoreFlow360.json` file

#### **Step 2: Verify Server Status**
- Check that all 6 MCP servers show as "Connected"
- Green status indicators for all servers
- No error messages in the logs

#### **Step 3: Test Claude Integration**
1. Open Claude in OpCode Desktop
2. Try these test commands:
   - "List files in my project"
   - "Show me the database schema"
   - "Run a Docker command"
   - "Check git status"

### **4. Available MCP Tools**

#### **Filesystem Server**
- `read_file` - Read file contents
- `write_file` - Write file contents
- `list_directory` - List directory contents
- `search_files` - Search for files
- `get_file_info` - Get file metadata

#### **Database Server**
- `query_database` - Execute SQL queries
- `get_schema` - Get database schema
- `list_tables` - List database tables
- `backup_database` - Create database backup

#### **Shell Server**
- `run_command` - Execute shell commands
- `get_processes` - List running processes
- `get_system_info` - Get system information
- `monitor_logs` - Monitor log files

#### **Cloudflare Proxy Server**
- `deploy_worker` - Deploy Cloudflare Worker
- `get_worker_logs` - Get worker logs
- `update_kv` - Update KV namespace
- `get_analytics` - Get analytics data

#### **Docker Server**
- `list_containers` - List Docker containers
- `run_container` - Run Docker container
- `build_image` - Build Docker image
- `get_container_logs` - Get container logs

#### **Git Server**
- `git_status` - Get git status
- `git_commit` - Make git commit
- `git_push` - Push to remote
- `git_pull` - Pull from remote

### **5. Troubleshooting**

#### **Common Issues**

**Issue: MCP Server Not Starting**
```bash
# Check if Python is in PATH
python --version

# Check if Node.js is in PATH
node --version

# Check if uvx is installed
pip install uvx
```

**Issue: Permission Denied**
```bash
# On Windows, run as Administrator
# Or check file permissions for the project directory
```

**Issue: Port Conflicts**
```bash
# Check if ports are in use
netstat -an | findstr :3000
netstat -an | findstr :5432
```

#### **Debug Commands**
```bash
# Test filesystem access
mcp-filesystem-server --test "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4"

# Test database connection
npx @executeautomation/database-server --test "C:\\Users\\ernij\\OneDrive\\Documents\\CoreFlow360 V4\\db.sqlite"

# Test Python MCP server
python cloudflare_proxy.py --test
```

### **6. Claude Integration Examples**

#### **File Operations**
```
Claude: "Read the package.json file and show me the dependencies"
Claude: "Create a new component file called Button.tsx"
Claude: "Search for all TypeScript files in the src directory"
```

#### **Database Operations**
```
Claude: "Show me the database schema"
Claude: "Query all users from the database"
Claude: "Create a new table for products"
```

#### **Docker Operations**
```
Claude: "List all running Docker containers"
Claude: "Build the Docker image for the app"
Claude: "Start the development environment"
```

#### **Git Operations**
```
Claude: "Check the git status"
Claude: "Commit all changes with message 'Update design system'"
Claude: "Push to the main branch"
```

#### **Cloudflare Operations**
```
Claude: "Deploy the worker to staging"
Claude: "Get the worker logs"
Claude: "Update the KV namespace with new data"
```

### **7. Security Considerations**

#### **Allowed Commands**
- Only whitelisted commands are allowed in shell server
- File access is limited to project directory
- Database access is read-only by default
- Docker access is limited to project containers

#### **Environment Variables**
- Sensitive data should be in environment variables
- API keys should not be hardcoded
- Use .env files for local development

### **8. Performance Optimization**

#### **File Size Limits**
- Maximum file size: 10MB (configurable)
- Large files are streamed, not loaded entirely
- Binary files are handled efficiently

#### **Connection Pooling**
- Database connections are pooled
- MCP servers use persistent connections
- Automatic reconnection on failure

### **9. Monitoring and Logs**

#### **Log Locations**
- OpCode Desktop logs: `%APPDATA%/OpCode/logs/`
- MCP server logs: Console output
- Application logs: `logs/` directory in project

#### **Health Checks**
```bash
# Check MCP server health
curl http://localhost:3000/health

# Check database health
sqlite3 db.sqlite "SELECT 1;"

# Check Docker health
docker ps
```

### **10. Advanced Configuration**

#### **Custom MCP Server**
```python
# Example custom MCP server
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("custom-server")

@server.list_tools()
async def list_tools() -> List[Tool]:
    return [
        Tool(
            name="custom_tool",
            description="Custom tool for CoreFlow360",
            inputSchema={
                "type": "object",
                "properties": {
                    "param": {"type": "string"}
                }
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> CallToolResult:
    if name == "custom_tool":
        return CallToolResult(
            content=[TextContent(type="text", text="Custom tool executed")]
        )
```

### **11. Success Checklist**

- [ ] OpCode Desktop is installed and running
- [ ] All 6 MCP servers are connected and green
- [ ] Claude can access files in the project
- [ ] Database queries work correctly
- [ ] Shell commands execute properly
- [ ] Docker operations function
- [ ] Git operations work
- [ ] Cloudflare proxy responds
- [ ] No error messages in logs
- [ ] All test commands execute successfully

### **12. Support and Resources**

#### **Documentation**
- [OpCode MCP Documentation](https://docs.opcode.com/mcp)
- [Claude Integration Guide](https://docs.anthropic.com/claude)
- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)

#### **Community**
- OpCode Discord: [Join Here](https://discord.gg/opcode)
- GitHub Issues: [Report Issues](https://github.com/opcode/mcp/issues)
- Stack Overflow: Tag `opcode-mcp`

**Your OpCode MCP configuration is now ready for seamless Claude integration with CoreFlow360!**
