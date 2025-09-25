/**
 * Message Renderer Component
 * Advanced markdown rendering with syntax highlighting, math, and custom elements
 */

import React, { useMemo } from 'react'
import { motion } from 'framer-motion'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import remarkMath from 'remark-math'
import rehypeKatex from 'rehype-katex'
import rehypeHighlight from 'rehype-highlight'
import rehypeRaw from 'rehype-raw'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark, oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { Copy, Check, Download, ExternalLink } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import type { MessageType } from '@/types/chat'
import 'katex/dist/katex.min.css'
import 'highlight.js/styles/github.css'

export interface MessageRendererProps {
  content: string
  isStreaming?: boolean
  messageType: MessageType
  className?: string
}

interface CodeBlockProps {
  children: string
  className?: string
  inline?: boolean
}

const StreamingCursor: React.FC = () => (
  <motion.span
    className="inline-block w-2 h-4 bg-blue-600 ml-1"
    animate={{ opacity: [1, 0, 1] }}
    transition={{ duration: 1, repeat: Infinity }}
  />
)

const CodeBlock: React.FC<CodeBlockProps> = ({ children, className, inline }) => {
  const [copied, setCopied] = React.useState(false)
  const language = className?.replace('language-', '') || 'text'

  const handleCopy = async () => {
    await navigator.clipboard.writeText(children)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (inline) {
    return (
      <code className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-800 rounded text-sm font-mono">
        {children}
      </code>
    )
  }

  return (
    <div className="relative group my-4">
      <div className="flex items-center justify-between bg-gray-100 dark:bg-gray-800 px-4 py-2 rounded-t-lg">
        <Badge variant="secondary" className="text-xs">
          {language}
        </Badge>
        <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2"
            onClick={handleCopy}
          >
            {copied ? (
              <Check className="w-3 h-3" />
            ) : (
              <Copy className="w-3 h-3" />
            )}
            <span className="ml-1 text-xs">
              {copied ? 'Copied' : 'Copy'}
            </span>
          </Button>
        </div>
      </div>
      <SyntaxHighlighter
        language={language}
        style={oneDark}
        customStyle={{
          margin: 0,
          borderTopLeftRadius: 0,
          borderTopRightRadius: 0,
        }}
        showLineNumbers={children.split('\n').length > 5}
      >
        {children}
      </SyntaxHighlighter>
    </div>
  )
}

const TableRenderer: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="overflow-x-auto my-4">
    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
      {children}
    </table>
  </div>
)

const LinkRenderer: React.FC<{ href?: string; children: React.ReactNode }> = ({ href, children }) => (
  <a
    href={href}
    className="text-blue-600 dark:text-blue-400 hover:underline inline-flex items-center"
    target="_blank"
    rel="noopener noreferrer"
  >
    {children}
    <ExternalLink className="w-3 h-3 ml-1" />
  </a>
)

const BlockquoteRenderer: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <blockquote className="border-l-4 border-blue-500 pl-4 py-2 my-4 bg-blue-50 dark:bg-blue-900/20 italic">
    {children}
  </blockquote>
)

const ListRenderer: React.FC<{ ordered?: boolean; children: React.ReactNode }> = ({ ordered, children }) => {
  const Component = ordered ? 'ol' : 'ul'
  return (
    <Component className={cn(
      "my-4 space-y-1",
      ordered ? "list-decimal list-inside" : "list-disc list-inside"
    )}>
      {children}
    </Component>
  )
}

const HeadingRenderer: React.FC<{ level: number; children: React.ReactNode }> = ({ level, children }) => {
  const Component = `h${level}` as keyof JSX.IntrinsicElements
  const styles = {
    1: "text-2xl font-bold mb-4 text-gray-900 dark:text-white",
    2: "text-xl font-semibold mb-3 text-gray-900 dark:text-white",
    3: "text-lg font-medium mb-2 text-gray-900 dark:text-white",
    4: "text-base font-medium mb-2 text-gray-800 dark:text-gray-200",
    5: "text-sm font-medium mb-1 text-gray-800 dark:text-gray-200",
    6: "text-sm font-medium mb-1 text-gray-700 dark:text-gray-300"
  }

  return (
    <Component className={styles[level as keyof typeof styles]}>
      {children}
    </Component>
  )
}

// Custom components for business-specific content
const InvoiceRenderer: React.FC<{ data: any }> = ({ data }) => (
  <div className="my-4 p-4 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800">
    <div className="flex items-center justify-between mb-2">
      <h4 className="font-semibold text-gray-900 dark:text-white">
        Invoice {data.number}
      </h4>
      <Badge variant={data.status === 'paid' ? 'default' : 'secondary'}>
        {data.status}
      </Badge>
    </div>
    <div className="grid grid-cols-2 gap-4 text-sm">
      <div>
        <span className="text-gray-500 dark:text-gray-400">Customer:</span>
        <span className="ml-2 text-gray-900 dark:text-white">{data.customer}</span>
      </div>
      <div>
        <span className="text-gray-500 dark:text-gray-400">Amount:</span>
        <span className="ml-2 text-gray-900 dark:text-white font-semibold">
          ${data.amount.toLocaleString()}
        </span>
      </div>
    </div>
  </div>
)

const MetricRenderer: React.FC<{ data: any }> = ({ data }) => (
  <div className="my-4 grid grid-cols-2 md:grid-cols-4 gap-4">
    {data.metrics.map((metric: any, index: number) => (
      <div
        key={index}
        className="p-3 bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg"
      >
        <div className="text-2xl font-bold text-gray-900 dark:text-white">
          {metric.value}
        </div>
        <div className="text-sm text-gray-600 dark:text-gray-400">
          {metric.label}
        </div>
        {metric.change && (
          <div className={cn(
            "text-xs font-medium",
            metric.change > 0 ? "text-green-600" : "text-red-600"
          )}>
            {metric.change > 0 ? '+' : ''}{metric.change}%
          </div>
        )}
      </div>
    ))}
  </div>
)

const parseCustomComponents = (content: string) => {
  // Parse custom component syntax like {{invoice:data}} or {{metrics:data}}
  return content.replace(/\{\{(\w+):([^}]+)\}\}/g, (match, type, data) => {
    try {
      const parsedData = JSON.parse(data)
      return `<div data-component="${type}" data-props='${JSON.stringify(parsedData)}'></div>`
    } catch {
      return match
    }
  })
}

export const MessageRenderer: React.FC<MessageRendererProps> = ({
  content,
  isStreaming = false,
  messageType,
  className
}) => {
  const processedContent = useMemo(() => {
    let processed = content

    // Parse custom business components
    processed = parseCustomComponents(processed)

    return processed
  }, [content])

  const components = {
    code: CodeBlock,
    table: TableRenderer,
    a: LinkRenderer,
    blockquote: BlockquoteRenderer,
    ul: ({ children }: any) => <ListRenderer>{children}</ListRenderer>,
    ol: ({ children }: any) => <ListRenderer ordered>{children}</ListRenderer>,
    h1: ({ children }: any) => <HeadingRenderer level={1}>{children}</HeadingRenderer>,
    h2: ({ children }: any) => <HeadingRenderer level={2}>{children}</HeadingRenderer>,
    h3: ({ children }: any) => <HeadingRenderer level={3}>{children}</HeadingRenderer>,
    h4: ({ children }: any) => <HeadingRenderer level={4}>{children}</HeadingRenderer>,
    h5: ({ children }: any) => <HeadingRenderer level={5}>{children}</HeadingRenderer>,
    h6: ({ children }: any) => <HeadingRenderer level={6}>{children}</HeadingRenderer>,
    p: ({ children }: any) => (
      <p className="mb-4 text-gray-900 dark:text-gray-100 leading-relaxed">
        {children}
        {isStreaming && <StreamingCursor />}
      </p>
    ),
    // Custom components
    div: ({ children, 'data-component': component, 'data-props': props, ...rest }: any) => {
      if (component && props) {
        const parsedProps = JSON.parse(props)
        switch (component) {
          case 'invoice':
            return <InvoiceRenderer data={parsedProps} />
          case 'metrics':
            return <MetricRenderer data={parsedProps} />
          default:
            return <div {...rest}>{children}</div>
        }
      }
      return <div {...rest}>{children}</div>
    }
  }

  return (
    <div className={cn(
      "prose prose-sm dark:prose-invert max-w-none",
      "prose-headings:text-gray-900 dark:prose-headings:text-white",
      "prose-p:text-gray-900 dark:prose-p:text-gray-100",
      "prose-a:text-blue-600 dark:prose-a:text-blue-400",
      "prose-strong:text-gray-900 dark:prose-strong:text-white",
      "prose-code:text-gray-900 dark:prose-code:text-gray-100",
      "prose-pre:bg-transparent prose-pre:p-0",
      className
    )}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm, remarkMath]}
        rehypePlugins={[rehypeKatex, rehypeHighlight, rehypeRaw]}
        components={components}
      >
        {processedContent}
      </ReactMarkdown>
    </div>
  )
}

export default MessageRenderer