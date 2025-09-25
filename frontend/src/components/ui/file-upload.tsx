import * as React from 'react'
import { cn } from '@/lib/utils'
import { Button } from './button'
import {
  Upload,
  File,
  X,
  CheckCircle,
  AlertCircle,
  FileText,
  Image,
  Film,
  Music,
  Archive,
  type LucideIcon
} from 'lucide-react'
import { Progress } from '@/@/components/ui/progress'

export interface FileUploadFile {
  id: string
  file: File
  progress?: number
  status?: 'pending' | 'uploading' | 'success' | 'error'
  error?: string
  url?: string
}

export interface FileUploadProps {
  value?: FileUploadFile[]
  onChange?: (files: FileUploadFile[]) => void
  onUpload?: (file: File) => Promise<string>
  accept?: string
  multiple?: boolean
  maxSize?: number
  maxFiles?: number
  disabled?: boolean
  className?: string
  variant?: 'default' | 'button' | 'compact'
}

export function FileUpload({
  value = [],
  onChange,
  onUpload,
  accept,
  multiple = false,
  maxSize = 10 * 1024 * 1024, // 10MB
  maxFiles = 10,
  disabled = false,
  className,
  variant = 'default'
}: FileUploadProps) {
  const [dragActive, setDragActive] = React.useState(false)
  const inputRef = React.useRef<HTMLInputElement>(null)

  const handleFiles = async (fileList: FileList | null) => {
    if (!fileList || disabled) return

    const newFiles: FileUploadFile[] = []
    const currentFileCount = value.length
    
    for (let i = 0; i < fileList.length; i++) {
      if (currentFileCount + newFiles.length >= maxFiles) break
      
      const file = fileList[i]
      
      if (maxSize && file.size > maxSize) {
        newFiles.push({
          id: Math.random().toString(36).substring(7),
          file,
          status: 'error',
          error: `File size exceeds ${formatFileSize(maxSize)} limit`
        })
        continue
      }

      const uploadFile: FileUploadFile = {
        id: Math.random().toString(36).substring(7),
        file,
        status: 'pending',
        progress: 0
      }

      newFiles.push(uploadFile)

      if (onUpload) {
        uploadFile.status = 'uploading'
        try {
          const url = await onUpload(file)
          uploadFile.url = url
          uploadFile.status = 'success'
          uploadFile.progress = 100
        } catch (error) {
          uploadFile.status = 'error'
          uploadFile.error = error instanceof Error ? error.message : 'Upload failed'
        }
      }
    }

    const updatedFiles = multiple ? [...value, ...newFiles] : newFiles
    onChange?.(updatedFiles)
  }

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (!disabled) {
      setDragActive(e.type === 'dragenter' || e.type === 'dragover')
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    if (!disabled) {
      handleFiles(e.dataTransfer.files)
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    handleFiles(e.target.files)
  }

  const handleRemove = (id: string) => {
    onChange?.(value.filter(f => f.id !== id))
  }

  const handleButtonClick = () => {
    inputRef.current?.click()
  }

  if (variant === 'button') {
    return (
      <div className={className}>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          multiple={multiple}
          onChange={handleChange}
          disabled={disabled}
          className="hidden"
        />
        <Button
          type="button"
          variant="outline"
          disabled={disabled}
          onClick={handleButtonClick}
        >
          <Upload className="h-4 w-4 mr-2" />
          Choose Files
        </Button>
        {value.length > 0 && (
          <FileList files={value} onRemove={handleRemove} compact />
        )}
      </div>
    )
  }

  return (
    <div className={cn("space-y-4", className)}>
      <div
        className={cn(
          "relative rounded-lg border-2 border-dashed p-8 text-center transition-colors",
          dragActive && "border-primary bg-primary/5",
          disabled && "opacity-50 cursor-not-allowed",
          !disabled && "hover:border-primary/50",
          variant === 'compact' && "p-4"
        )}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          multiple={multiple}
          onChange={handleChange}
          disabled={disabled}
          className="hidden"
        />
        
        <div className="flex flex-col items-center gap-2">
          <Upload className={cn(
            "text-muted-foreground",
            variant === 'default' && "h-10 w-10",
            variant === 'compact' && "h-8 w-8"
          )} />
          <div className="space-y-1">
            <p className="text-sm font-medium">
              {dragActive ? 'Drop files here' : 'Drop files here or click to upload'}
            </p>
            <p className="text-xs text-muted-foreground">
              {accept && `Accepted files: ${accept}`}
              {maxSize && ` • Max size: ${formatFileSize(maxSize)}`}
              {multiple && maxFiles && ` • Max files: ${maxFiles}`}
            </p>
          </div>
          <Button
            type="button"
            variant="secondary"
            size={variant === 'compact' ? 'sm' : 'default'}
            disabled={disabled}
            onClick={handleButtonClick}
          >
            Browse Files
          </Button>
        </div>
      </div>

      {value.length > 0 && (
        <FileList files={value} onRemove={handleRemove} />
      )}
    </div>
  )
}

interface FileListProps {
  files: FileUploadFile[]
  onRemove?: (id: string) => void
  compact?: boolean
}

function FileList({ files, onRemove, compact = false }: FileListProps) {
  return (
    <div className={cn(
      "space-y-2",
      compact && "mt-2"
    )}>
      {files.map(file => (
        <FileItem
          key={file.id}
          file={file}
          onRemove={() => onRemove?.(file.id)}
          compact={compact}
        />
      ))}
    </div>
  )
}

interface FileItemProps {
  file: FileUploadFile
  onRemove?: () => void
  compact?: boolean
}

function FileItem({ file, onRemove, compact }: FileItemProps) {
  const Icon = getFileIcon(file.file.type)
  const statusIcon = {
    pending: null,
    uploading: null,
    success: CheckCircle,
    error: AlertCircle
  }[file.status || 'pending']

  const StatusIcon = statusIcon

  return (
    <div className={cn(
      "flex items-center gap-3 rounded-lg border p-3",
      compact && "p-2",
      file.status === 'error' && "border-destructive bg-destructive/5"
    )}>
      <Icon className={cn(
        "shrink-0 text-muted-foreground",
        compact ? "h-4 w-4" : "h-5 w-5"
      )} />
      
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className={cn(
            "font-medium truncate",
            compact ? "text-xs" : "text-sm"
          )}>
            {file.file.name}
          </p>
          {StatusIcon && (
            <StatusIcon className={cn(
              "shrink-0",
              compact ? "h-3 w-3" : "h-4 w-4",
              file.status === 'success' && "text-green-500",
              file.status === 'error' && "text-destructive"
            )} />
          )}
        </div>
        
        {!compact && (
          <p className="text-xs text-muted-foreground">
            {formatFileSize(file.file.size)}
            {file.error && (
              <span className="text-destructive"> • {file.error}</span>
            )}
          </p>
        )}
        
        {file.status === 'uploading' && file.progress !== undefined && (
          <Progress value={file.progress} className="mt-2 h-1" />
        )}
      </div>
      
      {onRemove && (
        <button
          onClick={onRemove}
          className="shrink-0 text-muted-foreground hover:text-foreground transition-colors"
        >
          <X className={compact ? "h-3 w-3" : "h-4 w-4"} />
        </button>
      )}
    </div>
  )
}

function getFileIcon(mimeType: string): LucideIcon {
  if (mimeType.startsWith('image/')) return Image
  if (mimeType.startsWith('video/')) return Film
  if (mimeType.startsWith('audio/')) return Music
  if (mimeType.includes('zip') || mimeType.includes('compressed')) return Archive
  if (mimeType.includes('pdf')) return FileText
  return File
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

export interface DropzoneProps extends Omit<FileUploadProps, 'variant'> {
  height?: number | string
}

export function Dropzone({
  height = 200,
  ...props
}: DropzoneProps) {
  return (
    <FileUpload
      {...props}
      variant="default"
      className={cn(
        props.className,
        "[&>div:first-child]:h-full [&>div:first-child]:flex [&>div:first-child]:items-center [&>div:first-child]:justify-center"
      )}
      style={{ minHeight: height }}
    />
  )
}