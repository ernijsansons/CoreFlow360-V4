-- Chat System Database Schema
-- Creates tables for conversation management and chat functionality

-- Conversations table
CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  user_id TEXT NOT NULL,
  business_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active, archived, deleted
  metadata TEXT, -- JSON metadata
  message_count INTEGER DEFAULT 0,
  last_message_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (business_id) REFERENCES businesses(id)
);

-- Chat messages table
CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL,
  type TEXT NOT NULL, -- user, assistant, system
  content TEXT NOT NULL,
  metadata TEXT, -- JSON metadata
  attachments TEXT, -- JSON array of file attachments
  sources TEXT, -- JSON array of sources/references
  context_used INTEGER DEFAULT 0, -- Boolean flag
  is_streaming INTEGER DEFAULT 0, -- Boolean flag
  timestamp TEXT NOT NULL,
  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

-- Chat files table (for file attachments)
CREATE TABLE IF NOT EXISTS chat_files (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  size INTEGER NOT NULL,
  url TEXT NOT NULL,
  thumbnail_url TEXT,
  uploaded_by TEXT NOT NULL,
  uploaded_at TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  message_id TEXT,
  FOREIGN KEY (uploaded_by) REFERENCES users(id),
  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
  FOREIGN KEY (message_id) REFERENCES chat_messages(id) ON DELETE SET NULL
);

-- Dismissed suggestions table (for learning)
CREATE TABLE IF NOT EXISTS dismissed_suggestions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  suggestion_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  reason TEXT,
  dismissed_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_conversations_user_id ON conversations(user_id);
CREATE INDEX IF NOT EXISTS idx_conversations_business_id ON conversations(business_id);
CREATE INDEX IF NOT EXISTS idx_conversations_status ON conversations(status);
CREATE INDEX IF NOT EXISTS idx_conversations_updated_at ON conversations(updated_at);

CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation_id ON chat_messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_type ON chat_messages(type);
CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp);

CREATE INDEX IF NOT EXISTS idx_chat_files_conversation_id ON chat_files(conversation_id);
CREATE INDEX IF NOT EXISTS idx_chat_files_uploaded_by ON chat_files(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_chat_files_uploaded_at ON chat_files(uploaded_at);

CREATE INDEX IF NOT EXISTS idx_dismissed_suggestions_user_id ON dismissed_suggestions(user_id);
CREATE INDEX IF NOT EXISTS idx_dismissed_suggestions_suggestion_id ON dismissed_suggestions(suggestion_id);