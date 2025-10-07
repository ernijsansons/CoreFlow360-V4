import { createFileRoute } from '@tanstack/react-router'
import { useAuthStore } from '@/stores'
import { LoginForm } from '@/modules/auth/login-form'
import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield,
  Zap,
  TrendingUp,
  Users,
  Award,
  ChevronRight,
  Sparkles,
  Globe,
  Building
} from 'lucide-react'

export const Route = createFileRoute('/login')({
  component: LoginPage,
  beforeLoad: () => {
    const { isAuthenticated } = useAuthStore.getState()

    // Redirect to dashboard if already authenticated
    if (isAuthenticated) {
      throw new Error('Already authenticated')
    }
  },
  meta: () => [
    {
      title: 'Login - CoreFlow360 | AI-Powered Business Platform',
      description: 'Access your AI-native ERP platform for scaling multiple businesses',
    },
  ],
})

// Testimonials data
const testimonials = [
  {
    quote: "CoreFlow360 helped us scale from $1M to $10M in 12 months",
    author: "Sarah Chen",
    role: "CEO, TechVentures",
    rating: 5,
  },
  {
    quote: "The AI automation saves us 40 hours per week on operations",
    author: "Marcus Johnson",
    role: "Founder, Growth Labs",
    rating: 5,
  },
  {
    quote: "Managing 5 businesses has never been this effortless",
    author: "Emma Rodriguez",
    role: "Serial Entrepreneur",
    rating: 5,
  },
]

// Feature highlights - Brand colors
const features = [
  {
    icon: Zap,
    title: "AI-Powered Automation",
    description: "Autonomous agents handle operations 24/7",
    color: "from-warning-400 to-warning-600",
  },
  {
    icon: TrendingUp,
    title: "Predictive Scaling",
    description: "AI anticipates growth needs proactively",
    color: "from-brand-primary-400 to-brand-accent-600",
  },
  {
    icon: Users,
    title: "Multi-Business Management",
    description: "Single dashboard for entire portfolio",
    color: "from-success-400 to-brand-teal-600",
  },
]

// Trust badges removed - not yet compliant

function LoginPage() {
  const [currentTestimonial, setCurrentTestimonial] = useState(0)
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 })
  const containerRef = useRef<HTMLDivElement>(null)

  // Rotate testimonials
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTestimonial((prev) => (prev + 1) % testimonials.length)
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  // Track mouse for parallax effect
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!containerRef.current) return
      const rect = containerRef.current.getBoundingClientRect()
      setMousePosition({
        x: ((e.clientX - rect.left) / rect.width - 0.5) * 2,
        y: ((e.clientY - rect.top) / rect.height - 0.5) * 2,
      })
    }

    const container = containerRef.current
    if (container) {
      container.addEventListener('mousemove', handleMouseMove)
      return () => container.removeEventListener('mousemove', handleMouseMove)
    }
  }, [])

  return (
    <div
      ref={containerRef}
      className="min-h-screen relative overflow-hidden bg-gradient-to-br from-gray-950 via-brand-primary-950 to-gray-950"
    >
      {/* Animated background layers - Brand colors */}
      <div className="absolute inset-0 pointer-events-none">
        {/* Gradient orbs with parallax - Brand colors */}
        <motion.div
          animate={{
            x: mousePosition.x * 50,
            y: mousePosition.y * 50,
          }}
          transition={{ type: 'spring', stiffness: 50, damping: 20 }}
          className="absolute -top-40 -left-40 w-96 h-96 bg-brand-primary-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob"
        />
        <motion.div
          animate={{
            x: mousePosition.x * -30,
            y: mousePosition.y * -30,
          }}
          transition={{ type: 'spring', stiffness: 50, damping: 20 }}
          className="absolute -bottom-40 -right-40 w-96 h-96 bg-brand-teal-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-2000"
        />
        <motion.div
          animate={{
            x: mousePosition.x * 40,
            y: mousePosition.y * -40,
          }}
          transition={{ type: 'spring', stiffness: 50, damping: 20 }}
          className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-brand-accent-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-4000"
        />

        {/* Particle field */}
        <div className="absolute inset-0">
          {[...Array(50)].map((_, i) => (
            <div
              key={i}
              className="absolute animate-float-particle"
              style={{
                left: `${Math.random() * 100}%`,
                top: `${Math.random() * 100}%`,
                animationDelay: `${Math.random() * 10}s`,
                animationDuration: `${15 + Math.random() * 10}s`,
              }}
            >
              <div className="w-1 h-1 bg-white/20 rounded-full" />
            </div>
          ))}
        </div>

        {/* Grid overlay */}
        <div
          className="absolute inset-0 bg-grid-pattern opacity-5"
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
          }}
        />
      </div>

      <div className="relative z-10 min-h-screen flex">
        {/* Left side - Feature showcase */}
        <div className="hidden lg:flex lg:w-1/2 p-12 flex-col justify-between">
          {/* Logo and tagline - Brand colors */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="flex items-center space-x-3"
          >
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-brand-primary-400 to-brand-accent-600 blur-lg opacity-75 animate-pulse-glow" />
              <div className="relative bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 p-3 rounded-xl shadow-primary-lg">
                <Sparkles className="h-8 w-8 text-white" />
              </div>
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">CoreFlow360</h1>
              <p className="text-brand-primary-200 text-sm">AI-First Business Platform</p>
            </div>
          </motion.div>

          {/* Main content area */}
          <div className="flex-1 flex flex-col justify-center py-12">
            {/* Animated feature cards */}
            <div className="space-y-6 mb-12">
              {features.map((feature, index) => (
                <motion.div
                  key={feature.title}
                  initial={{ opacity: 0, x: -50 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.2, duration: 0.5 }}
                  whileHover={{ x: 10, transition: { duration: 0.2 } }}
                  className="group relative"
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-white/5 to-white/10 rounded-2xl transform transition-transform group-hover:scale-105" />
                  <div className="relative bg-white/5 backdrop-blur-xl rounded-2xl p-6 border border-white/10 group-hover:border-white/20 transition-all duration-300">
                    <div className="flex items-start space-x-4">
                      <div className={`bg-gradient-to-br ${feature.color} p-3 rounded-xl`}>
                        <feature.icon className="h-6 w-6 text-white" />
                      </div>
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-white mb-1">{feature.title}</h3>
                        <p className="text-brand-primary-200 text-sm">{feature.description}</p>
                      </div>
                      <ChevronRight className="h-5 w-5 text-white/40 group-hover:text-white/80 transform group-hover:translate-x-1 transition-all" />
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Testimonial carousel */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.8, duration: 0.5 }}
              className="relative h-32"
            >
              <AnimatePresence mode="wait">
                <motion.div
                  key={currentTestimonial}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.5 }}
                  className="absolute inset-0"
                >
                  <div className="bg-gradient-to-r from-brand-primary-500/10 to-brand-accent-500/10 backdrop-blur-xl rounded-2xl p-6 border border-white/10">
                    <div className="flex items-start space-x-1 mb-3">
                      {[...Array(testimonials[currentTestimonial].rating)].map((_, i) => (
                        <svg
                          key={i}
                          className="w-4 h-4 text-warning-400 fill-current"
                          viewBox="0 0 20 20"
                        >
                          <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                        </svg>
                      ))}
                    </div>
                    <p className="text-white/90 text-sm mb-3 italic">
                      "{testimonials[currentTestimonial].quote}"
                    </p>
                    <div className="flex items-center space-x-2">
                      <div className="w-8 h-8 bg-gradient-to-br from-brand-primary-400 to-brand-accent-400 rounded-full" />
                      <div>
                        <p className="text-white text-sm font-medium">
                          {testimonials[currentTestimonial].author}
                        </p>
                        <p className="text-brand-primary-300 text-xs">
                          {testimonials[currentTestimonial].role}
                        </p>
                      </div>
                    </div>
                  </div>
                </motion.div>
              </AnimatePresence>

              {/* Testimonial indicators - Brand colors */}
              <div className="absolute -bottom-6 left-1/2 transform -translate-x-1/2 flex space-x-2">
                {testimonials.map((_, index) => (
                  <button
                    key={index}
                    onClick={() => setCurrentTestimonial(index)}
                    className={`w-2 h-2 rounded-full transition-all duration-300 ${
                      index === currentTestimonial
                        ? 'w-8 bg-gradient-to-r from-brand-primary-400 to-brand-accent-400'
                        : 'bg-white/30 hover:bg-white/50'
                    }`}
                    aria-label={`Go to testimonial ${index + 1}`}
                  />
                ))}
              </div>
            </motion.div>
          </div>

        </div>

        {/* Right side - Login form */}
        <div className="flex-1 flex items-center justify-center p-8">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5 }}
            className="w-full max-w-md"
          >
            {/* 3D floating card container */}
            <motion.div
              animate={{
                rotateX: mousePosition.y * 5,
                rotateY: mousePosition.x * 5,
              }}
              transition={{ type: 'spring', stiffness: 100, damping: 30 }}
              style={{ perspective: 1000 }}
              className="relative"
            >
              {/* Glow effect - Brand colors */}
              <div className="absolute -inset-4 bg-gradient-to-r from-brand-primary-600 via-brand-accent-600 to-brand-teal-600 rounded-3xl opacity-75 blur-2xl animate-pulse-glow" />

              {/* Main card */}
              <div className="relative bg-white/10 backdrop-blur-2xl rounded-3xl p-8 border border-white/20 shadow-2xl">
                {/* Card inner glow - Brand colors */}
                <div className="absolute inset-0 bg-gradient-to-br from-brand-primary-500/10 via-transparent to-brand-teal-500/10 rounded-3xl pointer-events-none" />

                {/* Mobile logo (shown on small screens) - Brand colors */}
                <div className="lg:hidden mb-8 flex justify-center">
                  <div className="flex items-center space-x-3">
                    <div className="relative">
                      <div className="absolute inset-0 bg-gradient-to-r from-brand-primary-400 to-brand-accent-600 blur-lg opacity-75" />
                      <div className="relative bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 p-2 rounded-xl shadow-primary-md">
                        <Sparkles className="h-6 w-6 text-white" />
                      </div>
                    </div>
                    <h1 className="text-2xl font-bold text-white">CoreFlow360</h1>
                  </div>
                </div>

                {/* Form header */}
                <div className="text-center mb-8 relative z-10">
                  <motion.h2
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                    className="text-3xl font-bold text-white mb-2"
                  >
                    Welcome Back
                  </motion.h2>
                  <motion.p
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="text-brand-primary-200"
                  >
                    Enter your credentials to access your portfolio
                  </motion.p>
                </div>

                {/* Login form component */}
                <div className="relative z-10">
                  <LoginForm />
                </div>

                {/* Sign up link - Brand colors */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className="mt-6 text-center relative z-10"
                >
                  <p className="text-sm text-brand-primary-200">
                    New to CoreFlow360?{' '}
                    <a
                      href="/register"
                      className="font-semibold text-white hover:text-brand-primary-100 transition-colors underline underline-offset-4"
                    >
                      Create an account
                    </a>
                  </p>
                </motion.div>

                {/* Enterprise link - Brand colors */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.6 }}
                  className="mt-4 text-center relative z-10"
                >
                  <a
                    href="/enterprise"
                    className="text-xs text-brand-primary-300 hover:text-white transition-colors"
                  >
                    Looking for Enterprise? Contact Sales →
                  </a>
                </motion.div>
              </div>
            </motion.div>
          </motion.div>
        </div>
      </div>

      {/* CSS for animations */}
      <style jsx>{`
        @keyframes blob {
          0% { transform: translate(0px, 0px) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 20px) scale(0.9); }
          100% { transform: translate(0px, 0px) scale(1); }
        }

        @keyframes float-particle {
          0% { transform: translateY(0px) translateX(0px); opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { transform: translateY(-100vh) translateX(100px); opacity: 0; }
        }

        @keyframes pulse-glow {
          0%, 100% { opacity: 0.5; }
          50% { opacity: 0.8; }
        }

        .animate-blob {
          animation: blob 20s infinite;
        }

        .animation-delay-2000 {
          animation-delay: 2s;
        }

        .animation-delay-4000 {
          animation-delay: 4s;
        }

        .animate-float-particle {
          animation: float-particle 20s infinite linear;
        }

        .animate-pulse-glow {
          animation: pulse-glow 3s ease-in-out infinite;
        }
      `}</style>
    </div>
  )
}