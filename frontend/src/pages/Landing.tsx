import React, { useState } from 'react'
import { Hero } from '@/components/landing/Hero'
import { Features } from '@/components/landing/Features'
import { Testimonials } from '@/components/landing/Testimonials'
import { Pricing } from '@/components/landing/Pricing'
import { Footer } from '@/components/landing/Footer'
import { features, testimonials, pricingTiers, type PricingTier } from '@/utils/mockData'
import { toast } from 'sonner'

export const Landing: React.FC = () => {
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [selectedTier, setSelectedTier] = useState<PricingTier | null>(null)

  const handleSignUp = (email: string) => {
    setIsModalOpen(true)
    toast.success(`Great! Let's get you started with ${email}`)
  }

  const handleSelectTier = (tier: PricingTier) => {
    setSelectedTier(tier)
    setIsModalOpen(true)
  }

  return (
    <>
      <Hero onSignUp={handleSignUp} />
      <Features features={features} />
      <Testimonials testimonials={testimonials} />
      <Pricing tiers={pricingTiers} onSelectTier={handleSelectTier} />
      <Footer />
      {/* SignUpModal temporarily disabled due to Headless UI compatibility issue */}
    </>
  )
}
