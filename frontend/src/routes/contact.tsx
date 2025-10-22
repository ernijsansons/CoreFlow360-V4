import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { PublicHeader } from '@/components/layouts/PublicHeader'

export const Route = createFileRoute('/contact')({
  component: ContactPage,
})

function ContactPage() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    company: '',
    businessCount: '1',
    subject: '',
    message: '',
  })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitStatus, setSubmitStatus] = useState<'idle' | 'success' | 'error'>('idle')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    setSubmitStatus('idle')

    try {
      // TODO: Integrate with backend API
      await new Promise(resolve => setTimeout(resolve, 1500)) // Simulate API call
      setSubmitStatus('success')
      setFormData({
        name: '',
        email: '',
        company: '',
        businessCount: '1',
        subject: '',
        message: '',
      })
    } catch {
      setSubmitStatus('error')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <PublicHeader />
      {/* Hero */}
      <section className="py-20 px-4 bg-gradient-to-br from-brand-primary/10 via-background to-brand-accent/10">
        <div className="max-w-7xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-brand-primary to-brand-accent bg-clip-text text-transparent">
            Get in Touch
          </h1>
          <p className="text-xl md:text-2xl text-muted-foreground max-w-3xl mx-auto">
            Have questions? Want to see a demo? Our team is here to help you scale your business portfolio with AI.
          </p>
        </div>
      </section>

      {/* Contact Options */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <div className="grid md:grid-cols-3 gap-8 mb-16">
            <div className="bg-card rounded-xl p-8 border border-border text-center hover:border-brand-primary transition-colors">
              <div className="text-4xl mb-4">💬</div>
              <h3 className="text-xl font-bold mb-2">Live Chat</h3>
              <p className="text-muted-foreground mb-4">
                Chat with our support team in real-time
              </p>
              <button className="text-brand-primary font-semibold hover:underline">
                Start Chat →
              </button>
            </div>

            <div className="bg-card rounded-xl p-8 border border-border text-center hover:border-brand-primary transition-colors">
              <div className="text-4xl mb-4">📧</div>
              <h3 className="text-xl font-bold mb-2">Email</h3>
              <p className="text-muted-foreground mb-4">
                Send us a message, we'll respond within 24 hours
              </p>
              <a href="mailto:support@coreflow360.com" className="text-brand-primary font-semibold hover:underline">
                support@coreflow360.com
              </a>
            </div>

            <div className="bg-card rounded-xl p-8 border border-border text-center hover:border-brand-primary transition-colors">
              <div className="text-4xl mb-4">🏢</div>
              <h3 className="text-xl font-bold mb-2">Enterprise Sales</h3>
              <p className="text-muted-foreground mb-4">
                Custom solutions for large organizations
              </p>
              <a href="mailto:enterprise@coreflow360.com" className="text-brand-primary font-semibold hover:underline">
                enterprise@coreflow360.com
              </a>
            </div>
          </div>

          {/* Contact Form */}
          <div className="max-w-3xl mx-auto">
            <div className="bg-card rounded-xl p-8 md:p-12 border border-border shadow-lg">
              <h2 className="text-3xl font-bold mb-2">Send Us a Message</h2>
              <p className="text-muted-foreground mb-8">
                Fill out the form below and we'll get back to you as soon as possible
              </p>

              {submitStatus === 'success' && (
                <div className="mb-6 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                  <p className="text-green-800 dark:text-green-200 font-semibold">
                    ✓ Message sent successfully! We'll get back to you within 24 hours.
                  </p>
                </div>
              )}

              {submitStatus === 'error' && (
                <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                  <p className="text-red-800 dark:text-red-200 font-semibold">
                    ✗ Failed to send message. Please try again or email us directly.
                  </p>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <label htmlFor="name" className="block text-sm font-semibold mb-2">
                      Full Name *
                    </label>
                    <input
                      type="text"
                      id="name"
                      required
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                      placeholder="John Doe"
                    />
                  </div>

                  <div>
                    <label htmlFor="email" className="block text-sm font-semibold mb-2">
                      Email Address *
                    </label>
                    <input
                      type="email"
                      id="email"
                      required
                      value={formData.email}
                      onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                      className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                      placeholder="john@example.com"
                    />
                  </div>
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <label htmlFor="company" className="block text-sm font-semibold mb-2">
                      Company Name
                    </label>
                    <input
                      type="text"
                      id="company"
                      value={formData.company}
                      onChange={(e) => setFormData({ ...formData, company: e.target.value })}
                      className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                      placeholder="Acme Inc."
                    />
                  </div>

                  <div>
                    <label htmlFor="businessCount" className="block text-sm font-semibold mb-2">
                      Number of Businesses
                    </label>
                    <select
                      id="businessCount"
                      value={formData.businessCount}
                      onChange={(e) => setFormData({ ...formData, businessCount: e.target.value })}
                      className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                    >
                      <option value="1">1 business</option>
                      <option value="2-5">2-5 businesses</option>
                      <option value="6-10">6-10 businesses</option>
                      <option value="10+">10+ businesses</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label htmlFor="subject" className="block text-sm font-semibold mb-2">
                    Subject *
                  </label>
                  <input
                    type="text"
                    id="subject"
                    required
                    value={formData.subject}
                    onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
                    className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary"
                    placeholder="How can we help you?"
                  />
                </div>

                <div>
                  <label htmlFor="message" className="block text-sm font-semibold mb-2">
                    Message *
                  </label>
                  <textarea
                    id="message"
                    required
                    rows={6}
                    value={formData.message}
                    onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                    className="w-full px-4 py-3 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary resize-none"
                    placeholder="Tell us more about what you need..."
                  />
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full px-8 py-4 bg-brand-primary hover:bg-brand-primary/90 text-white rounded-lg text-lg font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
                >
                  {isSubmitting ? 'Sending...' : 'Send Message'}
                </button>

                <p className="text-sm text-muted-foreground text-center">
                  By submitting this form, you agree to our Privacy Policy and Terms of Service.
                </p>
              </form>
            </div>
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">Quick Answers</h2>

          <div className="space-y-4">
            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">What's your typical response time?</summary>
              <p className="mt-4 text-muted-foreground">
                We respond to all inquiries within 24 hours during business days. Enterprise customers with SLA agreements receive priority support with guaranteed response times.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">Can I schedule a demo?</summary>
              <p className="mt-4 text-muted-foreground">
                Absolutely! Mention in the message that you'd like a demo, and we'll send you a calendar link to book a personalized walkthrough of CoreFlow360.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">Do you offer consulting services?</summary>
              <p className="mt-4 text-muted-foreground">
                Yes, we offer implementation consulting, business process optimization, and custom AI agent development for Premium and Enterprise customers. Contact our sales team for details.
              </p>
            </details>

            <details className="bg-card rounded-lg p-6 border border-border">
              <summary className="font-semibold cursor-pointer">How do I report a bug or technical issue?</summary>
              <p className="mt-4 text-muted-foreground">
                For technical issues, please use the in-app support chat or email support@coreflow360.com with details about the issue. Include screenshots if possible for faster resolution.
              </p>
            </details>
          </div>
        </div>
      </section>

      {/* Office Info (Optional) */}
      <section className="py-20 px-4">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold text-center mb-12">Our Global Presence</h2>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="text-4xl mb-4">🇺🇸</div>
              <h3 className="text-xl font-bold mb-2">United States (HQ)</h3>
              <p className="text-muted-foreground">
                San Francisco, CA<br />
                North America Operations
              </p>
            </div>

            <div className="text-center">
              <div className="text-4xl mb-4">🇪🇺</div>
              <h3 className="text-xl font-bold mb-2">Europe</h3>
              <p className="text-muted-foreground">
                London, UK<br />
                European Operations
              </p>
            </div>

            <div className="text-center">
              <div className="text-4xl mb-4">🌏</div>
              <h3 className="text-xl font-bold mb-2">Asia-Pacific</h3>
              <p className="text-muted-foreground">
                Singapore<br />
                APAC Operations
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
