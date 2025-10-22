import React, { Fragment } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { XMarkIcon } from '@heroicons/react/24/outline'
import { toast } from 'sonner'

const signUpSchema = z.object({
  email: z.string().email('Please enter a valid email'),
  fullName: z.string().min(2, 'Name must be at least 2 characters'),
  company: z.string().optional(),
})

type SignUpFormData = z.infer<typeof signUpSchema>

interface SignUpModalProps {
  isOpen: boolean
  onClose: () => void
  tierName?: string
}

export const SignUpModal: React.FC<SignUpModalProps> = ({ isOpen, onClose, tierName }) => {
  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<SignUpFormData>({
    resolver: zodResolver(signUpSchema),
  })

  const onSubmit = (data: SignUpFormData) => {
    // Stub auth: save to localStorage
    localStorage.setItem('auth_token', 'demo_token_' + Date.now())
    localStorage.setItem('user_email', data.email)
    toast.success(`Welcome aboard! Check your email to complete setup.`)
    reset()
    onClose()
  }

  return (
    <Transition appear show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white p-8 shadow-xl transition-all dark:bg-gray-800">
                <div className="flex items-start justify-between">
                  <Dialog.Title className="text-2xl font-bold text-gray-900 dark:text-white">
                    {tierName ? `Start ${tierName} Plan` : 'Create Your Account'}
                  </Dialog.Title>
                  <button
                    onClick={onClose}
                    className="rounded-lg p-1 hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    <XMarkIcon className="h-6 w-6 text-gray-500" />
                  </button>
                </div>

                <form onSubmit={handleSubmit(onSubmit)} className="mt-6 space-y-4">
                  <div>
                    <label htmlFor="fullName" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Full Name
                    </label>
                    <input
                      type="text"
                      id="fullName"
                      {...register('fullName')}
                      className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-brand-primary-500 focus:outline-none focus:ring-2 focus:ring-brand-primary-500 dark:border-gray-600 dark:bg-gray-700 dark:text-white"
                    />
                    {errors.fullName && (
                      <p className="mt-1 text-sm text-red-600">{errors.fullName.message}</p>
                    )}
                  </div>

                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Email Address
                    </label>
                    <input
                      type="email"
                      id="email"
                      {...register('email')}
                      className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-brand-primary-500 focus:outline-none focus:ring-2 focus:ring-brand-primary-500 dark:border-gray-600 dark:bg-gray-700 dark:text-white"
                    />
                    {errors.email && <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>}
                  </div>

                  <div>
                    <label htmlFor="company" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                      Company (Optional)
                    </label>
                    <input
                      type="text"
                      id="company"
                      {...register('company')}
                      className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2 focus:border-brand-primary-500 focus:outline-none focus:ring-2 focus:ring-brand-primary-500 dark:border-gray-600 dark:bg-gray-700 dark:text-white"
                    />
                  </div>

                  <button
                    type="submit"
                    className="w-full rounded-lg bg-gradient-to-r from-brand-primary-600 to-brand-accent-600 px-6 py-3 font-semibold text-white transition-all hover:from-brand-primary-700 hover:to-brand-accent-700 focus:outline-none focus:ring-2 focus:ring-brand-primary-500 focus:ring-offset-2"
                  >
                    Create Account
                  </button>
                </form>

                <p className="mt-4 text-center text-sm text-gray-600 dark:text-gray-400">
                  By signing up, you agree to our{' '}
                  <a href="/terms" className="text-brand-primary-600 hover:underline">
                    Terms
                  </a>{' '}
                  and{' '}
                  <a href="/privacy" className="text-brand-primary-600 hover:underline">
                    Privacy Policy
                  </a>
                </p>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}
