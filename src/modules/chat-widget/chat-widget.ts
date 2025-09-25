// Real-time Chat Widget for Website Integration
// Connects to CoreFlow360 AI-Native CRM for instant lead qualification

export interface ChatWidgetConfig {
  businessId: string;
  apiEndpoint: string;
  theme: {
    primaryColor: string;
    textColor: string;
    backgroundColor: string;
    borderRadius: string;
    fontFamily: string;
  };
  behavior: {
    autoOpen: boolean;
    openDelay: number;
    welcomeMessage: string;
    offlineMessage: string;
    enableFileUpload: boolean;
    enableEmoji: boolean;
    enableTypingIndicator: boolean;
  };
  qualification: {
    enableAutoQualification: boolean;
    qualificationThreshold: number;
    collectEmail: boolean;
    collectPhone: boolean;
    enableMeetingBooking: boolean;
  };
  integrations: {
    googleAnalytics?: string;
    facebookPixel?: string;
    customTracking?: string[];
  };
}

export class ChatWidget {
  private config: ChatWidgetConfig;
  private sessionId: string;
  private isOpen: boolean = false;
  private messages: Array<{ id: string; message: string; sender: 'visitor' | 'ai'; timestamp: string }> = [];
  private isTyping: boolean = false;
  private qualified: boolean = false;
  private visitorInfo: any = {};

  constructor(config: Partial<ChatWidgetConfig>) {
    this.config = {
      businessId: '',
      apiEndpoint: 'https://api.coreflow360.com/lead-ingestion',
      theme: {
        primaryColor: '#007bff',
        textColor: '#333333',
        backgroundColor: '#ffffff',
        borderRadius: '8px',
        fontFamily: 'system-ui, -apple-system, sans-serif'
      },
      behavior: {
        autoOpen: false,
        openDelay: 3000,
        welcomeMessage: 'Hi! How can I help you today?',
        offlineMessage: 'We\'re currently offline. Please leave a message!',
        enableFileUpload: false,
        enableEmoji: true,
        enableTypingIndicator: true
      },
      qualification: {
        enableAutoQualification: true,
        qualificationThreshold: 70,
        collectEmail: true,
        collectPhone: false,
        enableMeetingBooking: true
      },
      integrations: {},
      ...config
    };

    this.sessionId = this.generateSessionId();
    this.init();
  }

  private init(): void {
    this.collectVisitorInfo();
    this.injectCSS();
    this.createWidget();
    this.bindEvents();

    if (this.config.behavior.autoOpen) {
      setTimeout(() => this.open(), this.config.behavior.openDelay);
    }
  }

  private collectVisitorInfo(): void {
    this.visitorInfo = {
      ip: '', // Would be collected server-side
      user_agent: navigator.userAgent,
      referrer: document.referrer,
      page_url: window.location.href,
      utm_source: this.getUrlParameter('utm_source'),
      utm_medium: this.getUrlParameter('utm_medium'),
      utm_campaign: this.getUrlParameter('utm_campaign'),
      screen_resolution: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language
    };
  }

  private getUrlParameter(name: string): string | null {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
  }

  private generateSessionId(): string {
    return 'chat_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
  }

  private injectCSS(): void {
    const css = `
      .cf360-chat-widget {
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 10000;
        font-family: ${this.config.theme.fontFamily};
      }

      .cf360-chat-bubble {
        width: 60px;
        height: 60px;
        background: ${this.config.theme.primaryColor};
        border-radius: 50%;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        transition: all 0.3s ease;
      }

      .cf360-chat-bubble:hover {
        transform: scale(1.05);
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
      }

      .cf360-chat-bubble svg {
        width: 24px;
        height: 24px;
        fill: white;
      }

      .cf360-chat-window {
        width: 350px;
        height: 500px;
        background: ${this.config.theme.backgroundColor};
        border-radius: ${this.config.theme.borderRadius};
        box-shadow: 0 5px 30px rgba(0,0,0,0.15);
        display: none;
        flex-direction: column;
        position: absolute;
        bottom: 80px;
        right: 0;
        overflow: hidden;
      }

      .cf360-chat-header {
        background: ${this.config.theme.primaryColor};
        color: white;
        padding: 15px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .cf360-chat-header h3 {
        margin: 0;
        font-size: 16px;
        font-weight: 600;
      }

      .cf360-chat-close {
        background: none;
        border: none;
        color: white;
        cursor: pointer;
        font-size: 18px;
        padding: 0;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .cf360-chat-messages {
        flex: 1;
        overflow-y: auto;
        padding: 15px;
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      .cf360-message {
        max-width: 80%;
        padding: 10px 12px;
        border-radius: 18px;
        word-wrap: break-word;
        line-height: 1.4;
      }

      .cf360-message.visitor {
        background: #e3f2fd;
        color: ${this.config.theme.textColor};
        align-self: flex-end;
        margin-left: auto;
      }

      .cf360-message.ai {
        background: #f5f5f5;
        color: ${this.config.theme.textColor};
        align-self: flex-start;
      }

      .cf360-typing-indicator {
        display: none;
        align-self: flex-start;
        background: #f5f5f5;
        padding: 10px 12px;
        border-radius: 18px;
        max-width: 60px;
      }

      .cf360-typing-dots {
        display: flex;
        gap: 4px;
      }

      .cf360-typing-dot {
        width: 6px;
        height: 6px;
        background: #999;
        border-radius: 50%;
        animation: cf360-typing 1.4s infinite ease-in-out;
      }

      .cf360-typing-dot:nth-child(1) { animation-delay: 0s; }
      .cf360-typing-dot:nth-child(2) { animation-delay: 0.2s; }
      .cf360-typing-dot:nth-child(3) { animation-delay: 0.4s; }

      @keyframes cf360-typing {
        0%, 60%, 100% { transform: translateY(0); opacity: 0.5; }
        30% { transform: translateY(-10px); opacity: 1; }
      }

      .cf360-chat-input-area {
        padding: 15px;
        border-top: 1px solid #eee;
      }

      .cf360-chat-input {
        width: 100%;
        border: 1px solid #ddd;
        border-radius: 20px;
        padding: 10px 15px;
        font-size: 14px;
        outline: none;
        resize: none;
        min-height: 20px;
        max-height: 80px;
        font-family: inherit;
      }

      .cf360-chat-input:focus {
        border-color: ${this.config.theme.primaryColor};
      }

      .cf360-qualification-form {
        padding: 15px;
        background: #f8f9fa;
        border-top: 1px solid #eee;
      }

      .cf360-qualification-title {
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 10px;
        color: ${this.config.theme.textColor};
      }

      .cf360-qualification-input {
        width: 100%;
        border: 1px solid #ddd;
        border-radius: 6px;
        padding: 8px 12px;
        margin-bottom: 8px;
        font-size: 14px;
        outline: none;
      }

      .cf360-qualification-input:focus {
        border-color: ${this.config.theme.primaryColor};
      }

      .cf360-meeting-prompt {
        background: #e8f5e8;
        border: 1px solid #4caf50;
        border-radius: 8px;
        padding: 12px;
        margin: 10px 0;
        text-align: center;
      }

      .cf360-meeting-button {
        background: #4caf50;
        color: white;
        border: none;
        border-radius: 6px;
        padding: 8px 16px;
        font-size: 14px;
        cursor: pointer;
        margin-top: 8px;
      }

      .cf360-hidden {
        display: none !important;
      }

      @media (max-width: 480px) {
        .cf360-chat-window {
          width: 100vw;
          height: 100vh;
          bottom: 0;
          right: 0;
          border-radius: 0;
        }
      }
    `;

    const styleSheet = document.createElement('style');
    styleSheet.textContent = css;
    document.head.appendChild(styleSheet);
  }

  private createWidget(): void {
    const widget = document.createElement('div');
    widget.className = 'cf360-chat-widget';
    widget.innerHTML = `
      <div class="cf360-chat-bubble" id="cf360-chat-bubble">
        <svg viewBox="0 0 24 24">
          <path d="M20 2H4c-1.1 0-2 .9-2 2v12c0
  1.1.9 2 2 2h4v3c0 .6.4 1 1 1 .2 0 .5-.1.7-.3L14.4 18H20c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H14l-2 2v-2H4V4h16v12z"/>
        </svg>
      </div>

      <div class="cf360-chat-window" id="cf360-chat-window">
        <div class="cf360-chat-header">
          <h3>Chat with us</h3>
          <button class="cf360-chat-close" id="cf360-chat-close">×</button>
        </div>

        <div class="cf360-chat-messages" id="cf360-chat-messages">
          <div class="cf360-message ai">
            ${this.config.behavior.welcomeMessage}
          </div>
          <div class="cf360-typing-indicator" id="cf360-typing-indicator">
            <div class="cf360-typing-dots">
              <div class="cf360-typing-dot"></div>
              <div class="cf360-typing-dot"></div>
              <div class="cf360-typing-dot"></div>
            </div>
          </div>
        </div>

        <div class="cf360-qualification-form cf360-hidden" id="cf360-qualification-form">
          <div class="cf360-qualification-title">To better assist you:</div>
          <input type="email" class="cf360-qualification-input" id="cf360-visitor-email" placeholder="Your email">
          <input type="text" class="cf360-qualification-input" id="cf360-visitor-name" placeholder="Your name">
          <input type="text" class="cf360-qualification-input" id="cf360-visitor-company" placeholder="Company name">
        </div>

        <div class="cf360-meeting-prompt cf360-hidden" id="cf360-meeting-prompt">
          <div>🎉 Great! You seem like a perfect fit. Would you like to schedule a quick 15-minute call?</div>
          <button class="cf360-meeting-button" id="cf360-schedule-meeting">Schedule Meeting</button>
        </div>

        <div class="cf360-chat-input-area">
       
    <textarea class="cf360-chat-input" id="cf360-chat-input" placeholder="Type your message..." rows="1"></textarea>
        </div>
      </div>
    `;

    document.body.appendChild(widget);

    // Add initial welcome message
    this.addMessage(this.config.behavior.welcomeMessage, 'ai');
  }

  private bindEvents(): void {
    const bubble = document.getElementById('cf360-chat-bubble');
    const closeBtn = document.getElementById('cf360-chat-close');
    const input = document.getElementById('cf360-chat-input') as HTMLTextAreaElement;
    const emailInput = document.getElementById('cf360-visitor-email') as HTMLInputElement;
    const nameInput = document.getElementById('cf360-visitor-name') as HTMLInputElement;
    const companyInput = document.getElementById('cf360-visitor-company') as HTMLInputElement;
    const meetingBtn = document.getElementById('cf360-schedule-meeting');

    bubble?.addEventListener('click', () => this.toggle());
    closeBtn?.addEventListener('click', () => this.close());

    input?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });

    input?.addEventListener('input', () => this.autoResize(input));

    // Qualification form events
    [emailInput, nameInput, companyInput].forEach(input => {
      input?.addEventListener('blur', () => this.updateVisitorInfo());
    });

    meetingBtn?.addEventListener('click', () => this.scheduleMeeting());

    // Auto-resize textarea
    this.autoResize(input);
  }

  private autoResize(textarea: HTMLTextAreaElement): void {
    if (!textarea) return;

    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 80) + 'px';
  }

  private toggle(): void {
    if (this.isOpen) {
      this.close();
    } else {
      this.open();
    }
  }

  private open(): void {
    const window = document.getElementById('cf360-chat-window');
    const bubble = document.getElementById('cf360-chat-bubble');

    if (window && bubble) {
      window.style.display = 'flex';
      bubble.style.display = 'none';
      this.isOpen = true;

      // Focus input
      const input = document.getElementById('cf360-chat-input') as HTMLTextAreaElement;
      setTimeout(() => input?.focus(), 100);

      // Track open event
      this.trackEvent('chat_opened');
    }
  }

  private close(): void {
    const window = document.getElementById('cf360-chat-window');
    const bubble = document.getElementById('cf360-chat-bubble');

    if (window && bubble) {
      window.style.display = 'none';
      bubble.style.display = 'flex';
      this.isOpen = false;

      // Track close event
      this.trackEvent('chat_closed');
    }
  }

  private async sendMessage(): Promise<void> {
    const input = document.getElementById('cf360-chat-input') as HTMLTextAreaElement;
    const message = input?.value.trim();

    if (!message) return;

    // Add visitor message
    this.addMessage(message, 'visitor');
    input.value = '';
    this.autoResize(input);

    // Show typing indicator
    this.showTyping();

    try {
      // Send to API
      const response = await this.sendToAPI(message);

      // Hide typing indicator
      this.hideTyping();

      // Add AI response
      if (response.success) {
        setTimeout(() => {
          this.addMessage(response.response, 'ai');

          // Handle qualification
          if (response.context?.visitor_qualified && !this.qualified) {
            this.qualified = true;
            this.showQualificationForm();

            if (response.meeting_booking_trigger) {
              setTimeout(() => this.showMeetingPrompt(), 2000);
            }
          }

          // Show qualification questions
          if (response.qualification_questions?.length > 0) {
            response.qualification_questions.forEach((question: string, index: number) => {
              setTimeout(() => this.addMessage(question, 'ai'), (index + 1) * 1000);
            });
          }

          // Transfer to human if needed
          if (response.transfer_to_human) {
            setTimeout(() => {
              this.addMessage("I'm connecting you with one of our specialists who can better assist you.", 'ai');
            }, 1000);
          }
        }, response.delay_ms || 1000);
      } else {
        this.addMessage("I'm sorry, I'm having trouble responding right now. Please try again.", 'ai');
      }
    } catch (error) {
      this.hideTyping();
      this.addMessage("I'm experiencing technical difficulties. Please try again or contact us directly.", 'ai');
    }

    // Track message
    this.trackEvent('message_sent', { message, qualified: this.qualified });
  }

  private async sendToAPI(message: string): Promise<any> {
    const payload = {
      id: this.generateId(),
      session_id: this.sessionId,
      message,
      timestamp: new Date().toISOString(),
      sender: 'visitor',
      visitor_info: this.visitorInfo,
      metadata: this.getVisitorMetadata()
    };

    const response = await fetch(`${this.config.apiEndpoint}/chat/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Business-ID': this.config.businessId
      },
      body: JSON.stringify(payload)
    });

    return response.json();
  }

  private getVisitorMetadata(): any {
    const emailInput = document.getElementById('cf360-visitor-email') as HTMLInputElement;
    const nameInput = document.getElementById('cf360-visitor-name') as HTMLInputElement;
    const companyInput = document.getElementById('cf360-visitor-company') as HTMLInputElement;

    return {
      email: emailInput?.value || null,
      name: nameInput?.value || null,
      company: companyInput?.value || null
    };
  }

  private addMessage(text: string, sender: 'visitor' | 'ai'): void {
    const messagesContainer = document.getElementById('cf360-chat-messages');
    if (!messagesContainer) return;

    const messageElement = document.createElement('div');
    messageElement.className = `cf360-message ${sender}`;
    messageElement.textContent = text;

    // Insert before typing indicator
    const typingIndicator = document.getElementById('cf360-typing-indicator');
    messagesContainer.insertBefore(messageElement, typingIndicator);

    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    // Store message
    this.messages.push({
      id: this.generateId(),
      message: text,
      sender,
      timestamp: new Date().toISOString()
    });
  }

  private showTyping(): void {
    const typingIndicator = document.getElementById('cf360-typing-indicator');
    if (typingIndicator) {
      typingIndicator.style.display = 'block';

      // Scroll to show typing
      const messagesContainer = document.getElementById('cf360-chat-messages');
      if (messagesContainer) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      }
    }
  }

  private hideTyping(): void {
    const typingIndicator = document.getElementById('cf360-typing-indicator');
    if (typingIndicator) {
      typingIndicator.style.display = 'none';
    }
  }

  private showQualificationForm(): void {
    if (!this.config.qualification.enableAutoQualification) return;

    const form = document.getElementById('cf360-qualification-form');
    if (form) {
      form.classList.remove('cf360-hidden');
    }
  }

  private showMeetingPrompt(): void {
    if (!this.config.qualification.enableMeetingBooking) return;

    const prompt = document.getElementById('cf360-meeting-prompt');
    if (prompt) {
      prompt.classList.remove('cf360-hidden');
    }
  }

  private updateVisitorInfo(): void {
    const emailInput = document.getElementById('cf360-visitor-email') as HTMLInputElement;
    const nameInput = document.getElementById('cf360-visitor-name') as HTMLInputElement;
    const companyInput = document.getElementById('cf360-visitor-company') as HTMLInputElement;

    // Send updated info to API
    if (emailInput?.value || nameInput?.value || companyInput?.value) {
      this.sendToAPI(`[SYSTEM] Visitor info updated:
  ${nameInput?.value || ''} (${emailInput?.value || ''}) from ${companyInput?.value || ''}`);
    }
  }

  private scheduleMeeting(): void {
    // This would integrate with calendar booking
    window.open('https://calendly.com/your-business/discovery-call', '_blank');

    this.addMessage("Great! I've opened our calendar in a new tab. Please select a time that works for you.", 'ai');
    this.trackEvent('meeting_booking_clicked');
  }

  private trackEvent(event: string, data: any = {}): void {
    // Google Analytics
    if (this.config.integrations.googleAnalytics && typeof gtag !== 'undefined') {
      gtag('event', event, {
        custom_parameter: JSON.stringify(data)
      });
    }

    // Facebook Pixel
    if (this.config.integrations.facebookPixel && typeof fbq !== 'undefined') {
      fbq('track', 'CustomEvent', { event, data });
    }

    // Custom tracking
    if (this.config.integrations.customTracking) {
      this.config.integrations.customTracking.forEach(tracker => {
        // Call custom tracking functions
        if (typeof window[tracker] === 'function') {
          window[tracker](event, data);
        }
      });
    }

    // Internal tracking
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }

  // Public API
  public setVisitorInfo(info: { email?: string; name?: string; company?: string; phone?: string }): void {
    const emailInput = document.getElementById('cf360-visitor-email') as HTMLInputElement;
    const nameInput = document.getElementById('cf360-visitor-name') as HTMLInputElement;
    const companyInput = document.getElementById('cf360-visitor-company') as HTMLInputElement;

    if (emailInput && info.email) emailInput.value = info.email;
    if (nameInput && info.name) nameInput.value = info.name;
    if (companyInput && info.company) companyInput.value = info.company;

    this.updateVisitorInfo();
  }

  public sendSystemMessage(message: string): void {
    this.addMessage(message, 'ai');
  }

  public openWidget(): void {
    this.open();
  }

  public closeWidget(): void {
    this.close();
  }
}

// Global initialization function
window.CoreFlow360Chat = {
  init: (config: Partial<ChatWidgetConfig>) => new ChatWidget(config)
};

// Auto-initialize if config is available
if (window.cf360ChatConfig) {
  window.CoreFlow360Chat.init(window.cf360ChatConfig);
}

// Type declarations for global objects
declare global {
  interface Window {
    CoreFlow360Chat: {
      init: (config: Partial<ChatWidgetConfig>) => ChatWidget;
    };
    cf360ChatConfig?: Partial<ChatWidgetConfig>;
    gtag?: (...args: any[]) => void;
    fbq?: (...args: any[]) => void;
    [key: string]: any;
  }
}