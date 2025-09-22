/**
 * Emoji Picker Component
 * Simple emoji picker for chat input
 */

import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

export interface EmojiPickerProps {
  onEmojiSelect: (emoji: string) => void
  onClose: () => void
  className?: string
}

const emojiCategories = {
  'Frequently Used': ['😀', '😂', '😊', '😍', '🤔', '👍', '👏', '🎉'],
  'Smileys': ['😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '😊', '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰'],
  'People': ['👋', '🤚', '🖐', '✋', '🖖', '👌', '🤌', '🤏', '✌', '🤞', '🤟', '🤘', '🤙', '👈', '👉', '👆'],
  'Objects': ['⌚', '📱', '📲', '💻', '⌨', '🖥', '🖨', '🖱', '🖲', '🕹', '🗜', '💽', '💾', '💿', '📀', '📼'],
  'Symbols': ['❤', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔', '❣', '💕', '💞', '💓', '💗', '💖']
}

export const EmojiPicker: React.FC<EmojiPickerProps> = ({
  onEmojiSelect,
  onClose,
  className
}) => {
  const [selectedCategory, setSelectedCategory] = useState('Frequently Used')
  const [search, setSearch] = useState('')

  const categories = Object.keys(emojiCategories)

  const filteredEmojis = search
    ? Object.values(emojiCategories).flat().filter(emoji =>
        emoji.includes(search.toLowerCase())
      )
    : emojiCategories[selectedCategory as keyof typeof emojiCategories]

  return (
    <motion.div
      className={cn(
        "bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700",
        "shadow-xl w-80 h-64 overflow-hidden",
        className
      )}
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
    >
      {/* Header */}
      <div className="p-3 border-b border-gray-200 dark:border-gray-700">
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search emojis..."
          className="h-8 text-sm"
        />
      </div>

      {/* Categories */}
      {!search && (
        <div className="flex overflow-x-auto scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-gray-600">
          {categories.map(category => (
            <Button
              key={category}
              variant={selectedCategory === category ? 'default' : 'ghost'}
              size="sm"
              className="px-3 py-1 text-xs whitespace-nowrap"
              onClick={() => setSelectedCategory(category)}
            >
              {category}
            </Button>
          ))}
        </div>
      )}

      {/* Emojis Grid */}
      <div className="flex-1 p-2 overflow-y-auto">
        <div className="grid grid-cols-8 gap-1">
          {filteredEmojis.map((emoji, index) => (
            <Button
              key={`${emoji}-${index}`}
              variant="ghost"
              className="w-8 h-8 p-0 text-lg hover:bg-gray-100 dark:hover:bg-gray-700"
              onClick={() => onEmojiSelect(emoji)}
            >
              {emoji}
            </Button>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

export default EmojiPicker