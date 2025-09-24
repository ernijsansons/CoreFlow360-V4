# 🔄 OpCode Clean Reinstall Guide

## 🗑️ **Step 1: Complete Uninstall**

### **1.1 Uninstall OpCode Desktop**
1. Press `Win + X`, select "Apps and Features"
2. Find "OpCode Desktop" in the list
3. Click on it and select "Uninstall"
4. Follow the uninstall wizard
5. **Restart your computer** (important!)

### **1.2 Clean All OpCode Files**
After restart, delete these folders if they exist:

**AppData Folders:**
1. Press `Win + R`, type `%APPDATA%`, press Enter
2. Delete the `OpCode` folder if it exists
3. Press `Win + R`, type `%LOCALAPPDATA%`, press Enter  
4. Delete the `OpCode` folder if it exists
5. Press `Win + R`, type `%PROGRAMDATA%`, press Enter
6. Delete the `OpCode` folder if it exists

**Program Files:**
1. Press `Win + R`, type `%PROGRAMFILES%`, press Enter
2. Delete the `OpCode` folder if it exists
3. Press `Win + R`, type `%PROGRAMFILES(X86)%`, press Enter
4. Delete the `OpCode` folder if it exists

### **1.3 Clean Registry (Optional but Recommended)**
1. Press `Win + R`, type `regedit`, press Enter
2. Navigate to `HKEY_CURRENT_USER\Software\`
3. Delete the `OpCode` key if it exists
4. Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\`
5. Delete the `OpCode` key if it exists
6. Close Registry Editor

## 📥 **Step 2: Fresh Installation**

### **2.1 Download Latest OpCode**
1. Go to https://opcode.com/download
2. Download the latest version for Windows
3. Make sure it's the official download

### **2.2 Install with Admin Rights**
1. Right-click the downloaded installer
2. Select "Run as administrator"
3. Follow the installation wizard
4. Install to the default location
5. **Don't configure MCP servers yet**

### **2.3 First Launch**
1. Launch OpCode Desktop
2. Go through the initial setup
3. **Skip MCP configuration for now**
4. Test basic functionality first

## ✅ **Step 3: Test Basic Functionality**

### **3.1 Test Commands**
Try these simple commands:
- "Hello, can you help me?"
- "What can you do?"
- "List files in my project directory"

### **3.2 Verify Features**
- File system access works
- Code editing works
- Terminal integration works
- No error messages

## 🎯 **Step 4: Success Criteria**

After clean reinstall, you should have:
- ✅ OpCode launches without errors
- ✅ Basic commands work
- ✅ No "Bad Request" errors
- ✅ No connection issues
- ✅ File system access works
- ✅ All core features functional

## 🚫 **Step 5: Don't Add MCP Yet**

**Important:** Don't add MCP servers back yet. Test OpCode thoroughly first:
1. Use it for a few days
2. Make sure it's stable
3. Only add MCP servers later if you really need them
4. Add them one at a time, testing each addition

## 🔧 **If Issues Persist**

If OpCode still doesn't work after clean reinstall:

### **Check System Requirements**
- Windows 10/11 (64-bit)
- At least 4GB RAM
- Internet connection
- No antivirus blocking OpCode

### **Alternative Solutions**
1. **Use Cursor with GitHub Copilot** (you already have Cursor)
2. **Use Claude web interface** (claude.ai)
3. **Use VS Code with AI extensions**
4. **Continue with your CoreFlow360 project using other tools**

## 📞 **Support**

If you need help:
- OpCode Support: https://opcode.com/support
- OpCode Discord: https://discord.gg/opcode
- Request refund if OpCode doesn't work

**The goal is to get you back to productive work on your CoreFlow360 project!**
