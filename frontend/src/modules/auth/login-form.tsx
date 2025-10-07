import { useState, useEffect } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useAuthStore } from '@/stores'
import { authService } from '@/lib/api/services'
import { Button } from '@/components/ui/button-refactored'
import { Label } from '@/components/ui/label'
import { toast } from 'sonner'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Loader2,
  Eye,
  EyeOff,
  Lock,
  Mail,
  Check,
  X,
  Fingerprint,
  KeyRound,
  Shield,
  ArrowRight
} from 'lucide-react'

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  rememberMe: z.boolean().optional(),
})

type LoginFormData = z.infer<typeof loginSchema>

// Password strength indicator
function PasswordStrength({ password }: { password: string }) {
  const [strength, setStrength] = useState(0)
  const [checks, setChecks] = useState({
    length: false,
    uppercase: false,
    lowercase: false,
    number: false,
    special: false,
  })

  useEffect(() => {
    const newChecks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    }
    setChecks(newChecks)

    const score = Object.values(newChecks).filter(Boolean).length
    setStrength(score)
  }, [password])

  if (!password) return null

  const strengthColors = [
    'bg-red-500',
    'bg-orange-500',
    'bg-yellow-500',
    'bg-lime-500',
    'bg-green-500',
  ]

  const strengthLabels = [
    'Very Weak',
    'Weak',
    'Fair',
    'Good',
    'Strong',
  ]

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.3 }}
      className="mt-2 space-y-2"
    >
      {/* Strength bar */}
      <div className="flex space-x-1">
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className={`flex-1 h-1 rounded-full transition-all duration-300 ${
              i < strength ? strengthColors[strength - 1] : 'bg-white/10'
            }`}
          />
        ))}
      </div>

      {/* Strength label */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-purple-200">
          {strengthLabels[strength - 1] || 'Very Weak'}
        </span>
        <div className="flex items-center space-x-2">
          {Object.entries(checks).map(([key, value]) => (
            <motion.div
              key={key}
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 500, damping: 30 }}
            >
              {value ? (
                <Check className="h-3 w-3 text-green-400" />
              ) : (
                <X className="h-3 w-3 text-white/20" />
              )}
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

// Premium input component
function PremiumInput({
  id,
  type = 'text',
  placeholder,
  icon: Icon,
  error,
  register,
  onFocus,
  onBlur,
  showPasswordToggle,
  ...props
}: {
  id: string
  type?: string
  placeholder: string
  icon?: React.ComponentType<{ className?: string }>
  error?: string
  register?: unknown
  onFocus?: () => void
  onBlur?: () => void
  showPasswordToggle?: boolean
  [key: string]: unknown
}) {
  const [showPassword, setShowPassword] = useState(false)
  const [isFocused, setIsFocused] = useState(false)

  const handleFocus = () => {
    setIsFocused(true)
    onFocus?.()
  }

  const handleBlur = () => {
    setIsFocused(false)
    onBlur?.()
  }

  const inputType = type === 'password' && showPassword ? 'text' : type

  return (
    <div className="relative group">
      {/* Input glow effect */}
      <div
        className={`absolute -inset-0.5 bg-gradient-to-r from-purple-600 to-pink-600 rounded-xl opacity-0 group-hover:opacity-50 blur transition-opacity duration-300 ${
          isFocused ? 'opacity-75' : ''
        }`}
      />

      {/* Input container */}
      <div className="relative">
        {/* Icon */}
        <div className="absolute left-4 top-1/2 transform -translate-y-1/2 pointer-events-none">
          <Icon
            className={`h-5 w-5 transition-colors duration-200 ${
              isFocused ? 'text-purple-300' : 'text-purple-400/60'
            }`}
          />
        </div>

        {/* Input field */}
        <input
          id={id}
          type={inputType}
          placeholder={placeholder}
          className={`
            w-full pl-12 pr-12 py-3.5
            bg-white/5 backdrop-blur-sm
            border border-white/10
            rounded-xl
            text-white placeholder-purple-300/50
            transition-all duration-300
            focus:outline-none focus:border-purple-400/50 focus:bg-white/10
            hover:bg-white/10 hover:border-white/20
            ${error ? 'border-red-400/50' : ''}
          `}
          onFocus={handleFocus}
          onBlur={handleBlur}
          {...register}
          {...props}
        />

        {/* Password visibility toggle */}
        {showPasswordToggle && (
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-4 top-1/2 transform -translate-y-1/2 text-purple-400/60 hover:text-purple-300 transition-colors"
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? (
              <EyeOff className="h-5 w-5" />
            ) : (
              <Eye className="h-5 w-5" />
            )}
          </button>
        )}

        {/* Success checkmark */}
        {!error && props.value && !showPasswordToggle && (
          <motion.div
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="absolute right-4 top-1/2 transform -translate-y-1/2"
          >
            <Check className="h-5 w-5 text-green-400" />
          </motion.div>
        )}
      </div>

      {/* Error message */}
      <AnimatePresence>
        {error && (
          <motion.p
            initial={{ opacity: 0, height: 0, y: -10 }}
            animate={{ opacity: 1, height: 'auto', y: 0 }}
            exit={{ opacity: 0, height: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="mt-1 text-xs text-red-400 pl-12"
            role="alert"
          >
            {error.message}
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  )
}

export function LoginForm() {
  const navigate = useNavigate()
  const { login } = useAuthStore()
  const [isLoading, setIsLoading] = useState(false)
  const [showBiometric, setShowBiometric] = useState(false)

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      rememberMe: false,
    },
  })

  const password = watch('password', '')

  // Check for biometric support
  useEffect(() => {
    if ('credentials' in navigator) {
      setShowBiometric(true)
    }
  }, [])

  const onSubmit = async (data: LoginFormData) => {
    setIsLoading(true)

    // Add realistic loading delay for premium feel
    await new Promise(resolve => setTimeout(resolve, 800))

    try {
      const response = await authService.login({
        email: data.email,
        password: data.password,
      })

      // Store authentication data
      login(response.token, response.refreshToken || response.token, response.user)

      // Success animation
      toast.success(
        <div className="flex items-center space-x-2">
          <div className="flex-shrink-0">
            <Shield className="h-5 w-5 text-green-500" />
          </div>
          <div>
            <p className="font-semibold">Login successful!</p>
            <p className="text-sm text-muted-foreground">
              Welcome back, {response.user.firstName}!
            </p>
          </div>
        </div>
      )

      // Navigate to dashboard with animation
      setTimeout(() => {
        navigate({ to: '/dashboard' })
      }, 500)
    } catch (error: unknown) {
      // Error animation
      const errorMessage = error instanceof Error ? error.message : 'Please check your credentials'
      toast.error(
        <div className="flex items-center space-x-2">
          <div className="flex-shrink-0">
            <X className="h-5 w-5 text-red-500" />
          </div>
          <div>
            <p className="font-semibold">Authentication failed</p>
            <p className="text-sm text-muted-foreground">
              {errorMessage}
            </p>
          </div>
        </div>
      )
    } finally {
      setIsLoading(false)
    }
  }

  const handleBiometricLogin = async () => {
    toast.info('Biometric authentication coming soon!')
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5" noValidate>
      {/* Email input */}
      <div className="space-y-2">
        <Label htmlFor="email" className="text-sm font-medium text-purple-200">
          Email Address
        </Label>
        <PremiumInput
          id="email"
          type="email"
          placeholder="name@company.com"
          icon={Mail}
          error={errors.email}
          register={register('email')}
          autoComplete="email"
          aria-required="true"
          aria-invalid={!!errors.email}
          aria-describedby={errors.email ? 'email-error' : undefined}
        />
      </div>

      {/* Password input */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <Label htmlFor="password" className="text-sm font-medium text-purple-200">
            Password
          </Label>
          <motion.a
            href="/auth/forgot-password"
            className="text-xs font-medium text-purple-300 hover:text-white transition-colors"
            whileHover={{ x: 3 }}
            transition={{ type: 'spring', stiffness: 400 }}
          >
            Forgot password?
          </motion.a>
        </div>
        <PremiumInput
          id="password"
          type="password"
          placeholder="Enter your password"
          icon={Lock}
          error={errors.password}
          register={register('password')}
          showPasswordToggle
          autoComplete="current-password"
          aria-required="true"
          aria-invalid={!!errors.password}
          aria-describedby={errors.password ? 'password-error' : undefined}
        />
        {password && <PasswordStrength password={password} />}
      </div>

      {/* Remember me checkbox */}
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <input
            id="remember-me"
            type="checkbox"
            className="h-4 w-4 rounded border-purple-400/30 bg-white/5 text-purple-600 focus:ring-purple-500 focus:ring-offset-0"
            {...register('rememberMe')}
          />
          <Label
            htmlFor="remember-me"
            className="ml-2 text-sm text-purple-200 cursor-pointer"
          >
            Keep me signed in
          </Label>
        </div>

        {/* Security badge */}
        <div className="flex items-center text-xs text-purple-300">
          <KeyRound className="h-3 w-3 mr-1" />
          256-bit encryption
        </div>
      </div>

      {/* Submit button */}
      <motion.div
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
      >
        <Button
          type="submit"
          className="w-full relative overflow-hidden group bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white border-0 py-3.5"
          disabled={isLoading}
          aria-busy={isLoading}
        >
          {/* Button gradient animation */}
          <div className="absolute inset-0 bg-gradient-to-r from-purple-400 to-pink-400 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />

          {/* Button content */}
          <span className="relative flex items-center justify-center">
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-5 w-5 animate-spin" aria-hidden="true" />
                Authenticating...
              </>
            ) : (
              <>
                Sign In Securely
                <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
              </>
            )}
          </span>
        </Button>
      </motion.div>

      {/* Biometric login */}
      {showBiometric && (
        <motion.button
          type="button"
          onClick={handleBiometricLogin}
          className="w-full py-3 border border-purple-400/30 rounded-xl text-purple-200 hover:text-white hover:bg-white/5 transition-all duration-300 flex items-center justify-center space-x-2 group"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <Fingerprint className="h-5 w-5 group-hover:text-purple-300 transition-colors" />
          <span>Use Biometric Authentication</span>
        </motion.button>
      )}

      {/* Divider */}
      <div className="relative my-8">
        <div className="absolute inset-0 flex items-center">
          <span className="w-full border-t border-purple-400/20" />
        </div>
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-transparent px-3 text-purple-300">
            Or continue with
          </span>
        </div>
      </div>

      {/* Social login buttons */}
      <div className="grid grid-cols-2 gap-3">
        <motion.button
          type="button"
          onClick={() => toast.info('Google SSO coming soon!')}
          className="flex items-center justify-center py-2.5 border border-purple-400/30 rounded-xl text-purple-200 hover:text-white hover:bg-white/5 transition-all duration-300 group"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          aria-label="Sign in with Google"
        >
          <svg className="mr-2 h-4 w-4" aria-hidden="true" viewBox="0 0 24 24">
            <path
              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              fill="#4285F4"
            />
            <path
              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              fill="#34A853"
            />
            <path
              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              fill="#FBBC05"
            />
            <path
              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              fill="#EA4335"
            />
          </svg>
          <span className="text-sm font-medium">Google</span>
        </motion.button>

        <motion.button
          type="button"
          onClick={() => toast.info('Microsoft SSO coming soon!')}
          className="flex items-center justify-center py-2.5 border border-purple-400/30 rounded-xl text-purple-200 hover:text-white hover:bg-white/5 transition-all duration-300 group"
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          aria-label="Sign in with Microsoft"
        >
          <svg className="mr-2 h-4 w-4" aria-hidden="true" viewBox="0 0 24 24">
            <path fill="#f25022" d="M1 1h10v10H1z" />
            <path fill="#00a4ef" d="M13 1h10v10H13z" />
            <path fill="#7fba00" d="M1 13h10v10H1z" />
            <path fill="#ffb900" d="M13 13h10v10H13z" />
          </svg>
          <span className="text-sm font-medium">Microsoft</span>
        </motion.button>
      </div>
    </form>
  )
}