import { useState, useEffect } from 'react'
import { Link } from '@tanstack/react-router'

interface OnboardingStep {
  title: string
  description: string
  action?: string
  actionLink?: string
  image?: string
}

const onboardingSteps: OnboardingStep[] = [
  {
    title: 'Welcome to CoreFlow360!',
    description: 'Manage multiple businesses with AI agents that handle all your operations autonomously. Let\'s get you started in just a few minutes.',
    action: 'Get Started',
    image: '🎉',
  },
  {
    title: 'Create Your First Business',
    description: 'Add your business details and we\'ll set up your workspace. You can add more businesses anytime from the portfolio dashboard.',
    action: 'Add Business',
    actionLink: '/dashboard',
    image: '🏢',
  },
  {
    title: 'Deploy AI Agents',
    description: 'Activate AI agents to handle your operations. Start with Finance and CRM agents—they\'ll begin working immediately in the background.',
    action: 'Deploy Agents',
    actionLink: '/dashboard',
    image: '🤖',
  },
  {
    title: 'Connect Your Tools',
    description: 'Link your existing tools like Stripe, PayPal, and accounting software. AI agents will sync data automatically.',
    action: 'Add Integrations',
    actionLink: '/settings',
    image: '🔌',
  },
  {
    title: 'You\'re All Set!',
    description: 'Your AI agents are now working for you 24/7. Check your dashboard to see real-time activity and insights.',
    action: 'Go to Dashboard',
    actionLink: '/dashboard',
    image: '✨',
  },
]

interface OnboardingTourProps {
  onComplete?: () => void
  onSkip?: () => void
}

export function OnboardingTour({ onComplete, onSkip }: OnboardingTourProps) {
  const [currentStep, setCurrentStep] = useState(0)
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    // Check if user has completed onboarding
    const hasCompletedOnboarding = localStorage.getItem('coreflow360_onboarding_completed')
    if (!hasCompletedOnboarding) {
      setIsVisible(true)
    }
  }, [])

  const handleNext = () => {
    if (currentStep < onboardingSteps.length - 1) {
      setCurrentStep(currentStep + 1)
    } else {
      handleComplete()
    }
  }

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
    }
  }

  const handleComplete = () => {
    localStorage.setItem('coreflow360_onboarding_completed', 'true')
    setIsVisible(false)
    onComplete?.()
  }

  const handleSkip = () => {
    localStorage.setItem('coreflow360_onboarding_completed', 'true')
    setIsVisible(false)
    onSkip?.()
  }

  if (!isVisible) {
    return null
  }

  const step = onboardingSteps[currentStep]
  const progress = ((currentStep + 1) / onboardingSteps.length) * 100

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-card rounded-2xl shadow-2xl max-w-2xl w-full border-2 border-brand-primary/20 overflow-hidden">
        {/* Progress Bar */}
        <div className="h-2 bg-muted">
          <div
            className="h-full bg-gradient-to-r from-brand-primary to-brand-accent transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* Content */}
        <div className="p-8 md:p-12">
          {/* Step Indicator */}
          <div className="flex items-center justify-between mb-6">
            <div className="text-sm font-semibold text-brand-primary">
              Step {currentStep + 1} of {onboardingSteps.length}
            </div>
            <button
              onClick={handleSkip}
              className="text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              Skip Tour
            </button>
          </div>

          {/* Image/Icon */}
          <div className="text-center mb-6">
            <div className="text-8xl mb-4">{step.image}</div>
          </div>

          {/* Title & Description */}
          <h2 className="text-3xl font-bold mb-4 text-center">{step.title}</h2>
          <p className="text-lg text-muted-foreground text-center mb-8 max-w-lg mx-auto">
            {step.description}
          </p>

          {/* Navigation Buttons */}
          <div className="flex items-center justify-between gap-4">
            <button
              onClick={handlePrevious}
              disabled={currentStep === 0}
              className="px-6 py-3 text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              ← Previous
            </button>

            <div className="flex gap-2">
              {onboardingSteps.map((_, index) => (
                <div
                  key={index}
                  className={`h-2 w-2 rounded-full transition-all ${
                    index === currentStep
                      ? 'bg-brand-primary w-8'
                      : index < currentStep
                      ? 'bg-brand-primary/50'
                      : 'bg-muted'
                  }`}
                />
              ))}
            </div>

            {currentStep < onboardingSteps.length - 1 ? (
              <button
                onClick={handleNext}
                className="px-8 py-3 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg font-semibold transition-colors shadow-md"
              >
                Next →
              </button>
            ) : (
              <Link
                to={step.actionLink || '/dashboard'}
                onClick={handleComplete}
                className="px-8 py-3 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg font-semibold transition-colors shadow-md"
              >
                {step.action || 'Get Started'}
              </Link>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// Setup Checklist Component
interface ChecklistItem {
  id: string
  title: string
  description: string
  completed: boolean
  actionLink?: string
}

export function SetupChecklist() {
  const [items, setItems] = useState<ChecklistItem[]>([
    {
      id: 'create-business',
      title: 'Create your first business',
      description: 'Add your business details and configure your workspace',
      completed: false,
      actionLink: '/dashboard',
    },
    {
      id: 'deploy-agents',
      title: 'Deploy AI agents',
      description: 'Activate Finance and CRM agents to start automating operations',
      completed: false,
      actionLink: '/dashboard',
    },
    {
      id: 'connect-integrations',
      title: 'Connect integrations',
      description: 'Link Stripe, PayPal, or other tools for seamless data sync',
      completed: false,
      actionLink: '/settings',
    },
    {
      id: 'invite-team',
      title: 'Invite team members (Optional)',
      description: 'Collaborate with your team on business operations',
      completed: false,
      actionLink: '/settings/team',
    },
    {
      id: 'explore-dashboard',
      title: 'Explore your dashboard',
      description: 'View AI agent activity and business analytics',
      completed: false,
      actionLink: '/dashboard',
    },
  ])

  const completedCount = items.filter(item => item.completed).length
  const progress = (completedCount / items.length) * 100

  const toggleItem = (id: string) => {
    setItems(prevItems =>
      prevItems.map(item =>
        item.id === id ? { ...item, completed: !item.completed } : item
      )
    )
  }

  return (
    <div className="bg-card rounded-xl p-6 border border-border shadow-sm">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-xl font-bold mb-1">Setup Checklist</h3>
          <p className="text-sm text-muted-foreground">
            Complete these steps to get the most out of CoreFlow360
          </p>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold text-brand-primary">
            {completedCount}/{items.length}
          </div>
          <p className="text-xs text-muted-foreground">Completed</p>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-6">
        <div className="h-3 bg-muted rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-brand-primary to-brand-accent transition-all duration-500"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Checklist Items */}
      <div className="space-y-3">
        {items.map((item) => (
          <div
            key={item.id}
            className={`flex items-start gap-4 p-4 rounded-lg border transition-colors ${
              item.completed
                ? 'bg-brand-primary/5 border-brand-primary/20'
                : 'bg-background border-border hover:border-brand-primary/40'
            }`}
          >
            <button
              onClick={() => toggleItem(item.id)}
              className={`flex-shrink-0 w-6 h-6 rounded-full border-2 flex items-center justify-center transition-colors ${
                item.completed
                  ? 'bg-brand-primary border-brand-primary'
                  : 'border-muted-foreground hover:border-brand-primary'
              }`}
            >
              {item.completed && (
                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                </svg>
              )}
            </button>

            <div className="flex-1">
              <h4 className={`font-semibold mb-1 ${item.completed ? 'line-through text-muted-foreground' : ''}`}>
                {item.title}
              </h4>
              <p className="text-sm text-muted-foreground">{item.description}</p>
            </div>

            {!item.completed && item.actionLink && (
              <Link
                to={item.actionLink}
                className="flex-shrink-0 px-4 py-2 text-sm bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg font-medium transition-colors"
              >
                Start
              </Link>
            )}
          </div>
        ))}
      </div>

      {completedCount === items.length && (
        <div className="mt-6 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg text-center">
          <p className="text-green-800 dark:text-green-200 font-semibold">
            🎉 Congratulations! You've completed the setup.
          </p>
        </div>
      )}
    </div>
  )
}
