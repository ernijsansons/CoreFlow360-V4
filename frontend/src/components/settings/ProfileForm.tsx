import * as React from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import * as z from 'zod'
import {
  Camera,
  User,
  Mail,
  Phone,
  Globe,
  Loader2,
  CheckCircle2,
  Upload
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { cn } from '@/lib/utils'

// Validation schema
const profileSchema = z.object({
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
  email: z.string().email('Invalid email address'),
  phone: z.string().optional(),
  username: z.string().min(3, 'Username must be at least 3 characters'),
  website: z.string().url('Invalid URL').optional().or(z.literal('')),
  bio: z.string().max(500, 'Bio must be less than 500 characters').optional(),
  country: z.string().optional(),
})

type ProfileFormData = z.infer<typeof profileSchema>

export function ProfileForm() {
  const [isLoading, setIsLoading] = React.useState(false)
  const [success, setSuccess] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [avatarPreview, setAvatarPreview] = React.useState<string | null>(null)
  const fileInputRef = React.useRef<HTMLInputElement>(null)

  const {
    register,
    handleSubmit,
    formState: { errors, isDirty },
    setValue,
    watch,
  } = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      username: 'johndoe',
      phone: '+1 (555) 123-4567',
      website: 'https://johndoe.com',
      bio: 'Senior Product Manager focused on enterprise SaaS solutions.',
      country: 'US',
    }
  })

  const onSubmit = async (data: ProfileFormData) => {
    setIsLoading(true)
    setError(null)
    setSuccess(false)

    try {
      // Mock API call
      await new Promise(resolve => setTimeout(resolve, 1500))

      // Simulate random error for demo
      if (Math.random() > 0.8) {
        throw new Error('Failed to update profile. Please try again.')
      }

      setSuccess(true)
      setTimeout(() => setSuccess(false), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const handleAvatarChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      // Check file size (max 5MB)
      if (file.size > 5 * 1024 * 1024) {
        setError('Avatar image must be less than 5MB')
        return
      }

      // Check file type
      if (!file.type.startsWith('image/')) {
        setError('Please select an image file')
        return
      }

      const reader = new FileReader()
      reader.onloadend = () => {
        setAvatarPreview(reader.result as string)
      }
      reader.readAsDataURL(file)
    }
  }

  const initials = `${watch('firstName')?.[0] || ''}${watch('lastName')?.[0] || ''}`.toUpperCase()

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      {success && (
        <Alert className="bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800">
          <CheckCircle2 className="h-4 w-4 text-green-600 dark:text-green-400" />
          <AlertTitle className="text-green-900 dark:text-green-100">
            Profile updated successfully
          </AlertTitle>
          <AlertDescription className="text-green-700 dark:text-green-300">
            Your profile information has been saved.
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Avatar Upload */}
      <div className="flex items-center space-x-6">
        <div className="relative">
          <Avatar className="h-24 w-24">
            <AvatarImage src={avatarPreview || undefined} />
            <AvatarFallback className="text-2xl">{initials}</AvatarFallback>
          </Avatar>
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="absolute bottom-0 right-0 p-1.5 bg-white dark:bg-gray-800 border rounded-full shadow-sm hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            aria-label="Change avatar"
          >
            <Camera className="h-4 w-4" />
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleAvatarChange}
            className="hidden"
            aria-label="Avatar file input"
          />
        </div>

        <div className="space-y-1">
          <Button type="button" variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
            <Upload className="h-4 w-4 mr-2" />
            Upload new photo
          </Button>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            JPG, GIF or PNG. Max size 5MB.
          </p>
        </div>
      </div>

      {/* Form Fields */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="firstName">First name</Label>
          <div className="relative">
            <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="firstName"
              placeholder="John"
              className="pl-10"
              {...register('firstName')}
              aria-invalid={!!errors.firstName}
              aria-describedby={errors.firstName ? 'firstName-error' : undefined}
            />
          </div>
          {errors.firstName && (
            <p id="firstName-error" className="text-xs text-red-500">
              {errors.firstName.message}
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="lastName">Last name</Label>
          <div className="relative">
            <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="lastName"
              placeholder="Doe"
              className="pl-10"
              {...register('lastName')}
              aria-invalid={!!errors.lastName}
              aria-describedby={errors.lastName ? 'lastName-error' : undefined}
            />
          </div>
          {errors.lastName && (
            <p id="lastName-error" className="text-xs text-red-500">
              {errors.lastName.message}
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="email"
              type="email"
              placeholder="john@example.com"
              className="pl-10"
              {...register('email')}
              aria-invalid={!!errors.email}
              aria-describedby={errors.email ? 'email-error' : undefined}
            />
          </div>
          {errors.email && (
            <p id="email-error" className="text-xs text-red-500">
              {errors.email.message}
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            placeholder="johndoe"
            {...register('username')}
            aria-invalid={!!errors.username}
            aria-describedby={errors.username ? 'username-error' : undefined}
          />
          {errors.username && (
            <p id="username-error" className="text-xs text-red-500">
              {errors.username.message}
            </p>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="phone">Phone number</Label>
          <div className="relative">
            <Phone className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              id="phone"
              type="tel"
              placeholder="+1 (555) 123-4567"
              className="pl-10"
              {...register('phone')}
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="country">Country</Label>
          <Select defaultValue="US" onValueChange={(value) => setValue('country', value)}>
            <SelectTrigger id="country">
              <SelectValue placeholder="Select country" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="US">United States</SelectItem>
              <SelectItem value="UK">United Kingdom</SelectItem>
              <SelectItem value="CA">Canada</SelectItem>
              <SelectItem value="AU">Australia</SelectItem>
              <SelectItem value="DE">Germany</SelectItem>
              <SelectItem value="FR">France</SelectItem>
              <SelectItem value="JP">Japan</SelectItem>
              <SelectItem value="Other">Other</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="website">Website</Label>
        <div className="relative">
          <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <Input
            id="website"
            type="url"
            placeholder="https://example.com"
            className="pl-10"
            {...register('website')}
            aria-invalid={!!errors.website}
            aria-describedby={errors.website ? 'website-error' : undefined}
          />
        </div>
        {errors.website && (
          <p id="website-error" className="text-xs text-red-500">
            {errors.website.message}
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="bio">Bio</Label>
        <textarea
          id="bio"
          className={cn(
            "flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background",
            "placeholder:text-muted-foreground",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
            "disabled:cursor-not-allowed disabled:opacity-50",
            errors.bio && "border-red-500"
          )}
          placeholder="Tell us about yourself..."
          {...register('bio')}
          aria-invalid={!!errors.bio}
          aria-describedby={errors.bio ? 'bio-error' : undefined}
        />
        <div className="flex justify-between">
          <div>
            {errors.bio && (
              <p id="bio-error" className="text-xs text-red-500">
                {errors.bio.message}
              </p>
            )}
          </div>
          <span className="text-xs text-gray-500">
            {watch('bio')?.length || 0}/500
          </span>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex justify-between">
        <Button
          type="button"
          variant="outline"
          disabled={!isDirty || isLoading}
          onClick={() => window.location.reload()}
        >
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={isLoading || !isDirty}
        >
          {isLoading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Saving...
            </>
          ) : (
            'Save changes'
          )}
        </Button>
      </div>
    </form>
  )
}