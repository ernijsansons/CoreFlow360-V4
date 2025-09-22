import type {
  CalendarSlot,
  CalendarProvider,
  CalendarEvent,
  Meeting,
  MeetingAttendee
} from '../types/crm';
import type { Env } from '../types/env';

export interface CalendarIntegration {
  getAvailableSlots(startDate: Date, endDate: Date, duration: number): Promise<CalendarSlot[]>;
  createEvent(event: CalendarEventRequest): Promise<string>; // Returns external event ID
  updateEvent(eventId: string, updates: Partial<CalendarEventRequest>): Promise<boolean>;
  deleteEvent(eventId: string): Promise<boolean>;
  getEvent(eventId: string): Promise<CalendarEvent | null>;
}

export interface CalendarEventRequest {
  title: string;
  description?: string;
  start: string; // ISO timestamp
  end: string; // ISO timestamp
  timezone: string;
  location?: string;
  attendees: Array<{
    email: string;
    name?: string;
    required?: boolean;
  }>;
  reminders?: Array<{
    method: 'email' | 'popup';
    minutes: number;
  }>;
  recurrence?: {
    frequency: 'daily' | 'weekly' | 'monthly';
    interval: number;
    count?: number;
    until?: string;
  };
}

export // TODO: Consider splitting CalendarService into smaller, focused classes
class CalendarService {
  private integrations = new Map<string, CalendarIntegration>();
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.initializeIntegrations();
  }

  private initializeIntegrations(): void {
    // Initialize Google Calendar integration if credentials are available
    if (this.env.GOOGLE_CALENDAR_CLIENT_ID) {
      this.integrations.set('google', new GoogleCalendarIntegration(this.env));
    }

    // Initialize Outlook integration if credentials are available
    if (this.env.OUTLOOK_CLIENT_ID) {
      this.integrations.set('outlook', new OutlookCalendarIntegration(this.env));
    }

    // Add CalDAV integration for generic calendar support
    this.integrations.set('caldav', new CalDAVIntegration(this.env));
  }

  async getAvailableSlots(
    provider: string,
    userId: string,
    startDate: Date,
    endDate: Date,
    durationMinutes: number = 30,
    businessHours?: { start: string; end: string; days: number[] }
  ): Promise<CalendarSlot[]> {
    try {
      const integration = this.integrations.get(provider);
      if (!integration) {
        throw new Error(`Calendar provider '${provider}' not supported`);
      }

      // Get all available slots from the calendar provider
      const allSlots = await integration.getAvailableSlots(startDate, endDate, durationMinutes);

      // Filter by business hours if specified
      if (businessHours) {
        return this.filterByBusinessHours(allSlots, businessHours);
      }

      return allSlots;

    } catch (error) {
      // Return fallback slots if calendar integration fails
      return this.generateFallbackSlots(startDate, endDate, durationMinutes);
    }
  }

  async createCalendarEvent(
    provider: string,
    userId: string,
    eventRequest: CalendarEventRequest
  ): Promise<string | null> {
    try {
      const integration = this.integrations.get(provider);
      if (!integration) {
        throw new Error(`Calendar provider '${provider}' not supported`);
      }

      const eventId = await integration.createEvent(eventRequest);

      // Log successful event creation

      return eventId;

    } catch (error) {
      return null;
    }
  }

  async updateCalendarEvent(
    provider: string,
    eventId: string,
    updates: Partial<CalendarEventRequest>
  ): Promise<boolean> {
    try {
      const integration = this.integrations.get(provider);
      if (!integration) {
        throw new Error(`Calendar provider '${provider}' not supported`);
      }

      return await integration.updateEvent(eventId, updates);

    } catch (error) {
      return false;
    }
  }

  async deleteCalendarEvent(provider: string, eventId: string): Promise<boolean> {
    try {
      const integration = this.integrations.get(provider);
      if (!integration) {
        throw new Error(`Calendar provider '${provider}' not supported`);
      }

      return await integration.deleteEvent(eventId);

    } catch (error) {
      return false;
    }
  }

  async sendCalendarInvite(meeting: Meeting): Promise<boolean> {
    try {
      // Create ICS file content
      const icsContent = this.generateICSContent(meeting);

      // Send email with calendar invite
      const emailService = new EmailService(this.env);
      const success = await emailService.sendCalendarInvite({
        to: meeting.attendees.map(a => a.email),
        subject: `Meeting Invitation: ${meeting.title}`,
        icsContent,
        meeting
      });

      return success;

    } catch (error) {
      return false;
    }
  }

  private filterByBusinessHours(
    slots: CalendarSlot[],
    businessHours: { start: string; end: string; days: number[] }
  ): CalendarSlot[] {
    return slots.filter(slot => {
      const startDate = new Date(slot.start);
      const dayOfWeek = startDate.getDay();
      const timeOfDay = startDate.toTimeString().substring(0, 5); // HH:MM format

      // Check if day is within business days
      if (!businessHours.days.includes(dayOfWeek)) {
        return false;
      }

      // Check if time is within business hours
      if (timeOfDay < businessHours.start || timeOfDay > businessHours.end) {
        return false;
      }

      return true;
    });
  }

  private generateFallbackSlots(
    startDate: Date,
    endDate: Date,
    durationMinutes: number
  ): CalendarSlot[] {
    const slots: CalendarSlot[] = [];
    const current = new Date(startDate);

    while (current < endDate) {
      // Skip weekends for fallback slots
      if (current.getDay() !== 0 && current.getDay() !== 6) {
        // Generate business hour slots (9 AM to 5 PM)
        for (let hour = 9; hour < 17; hour++) {
          if (hour === 12) continue; // Skip lunch hour

          const slotStart = new Date(current);
          slotStart.setHours(hour, 0, 0, 0);

          const slotEnd = new Date(slotStart);
          slotEnd.setMinutes(slotEnd.getMinutes() + durationMinutes);

          slots.push({
            start: slotStart.toISOString(),
            end: slotEnd.toISOString(),
            timezone: 'UTC',
            available: true,
            calendar_owner: 'system'
          });
        }
      }

      current.setDate(current.getDate() + 1);
    }

    return slots.slice(0, 20); // Limit to 20 fallback slots
  }

  private generateICSContent(meeting: Meeting): string {
    const formatDate = (date: string) => {
      return new Date(date).toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
    };

    const icsContent = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//CoreFlow360//Meeting Scheduler//EN',
      'BEGIN:VEVENT',
      `UID:${meeting.id}@coreflow360.com`,
      `DTSTART:${formatDate(meeting.scheduled_start)}`,
      `DTEND:${formatDate(meeting.scheduled_end)}`,
      `SUMMARY:${meeting.title}`,
      `DESCRIPTION:${meeting.description || ''}`,
      `LOCATION:${meeting.location || meeting.meeting_url || ''}`,
      `STATUS:CONFIRMED`,
      `SEQUENCE:0`,
      ...meeting.attendees.map(attendee =>
        `ATTENDEE;CN=${attendee.name || attendee.email};RSVP=TRUE:mailto:${attendee.email}`
      ),
      'END:VEVENT',
      'END:VCALENDAR'
    ].join('\r\n');

    return icsContent;
  }

  // Method to check if a user has calendar integration set up
  async hasCalendarIntegration(userId: string, provider: string): Promise<boolean> {
    // In real implementation, check user's calendar provider settings in database
    return this.integrations.has(provider);
  }

  // Get supported calendar providers
  getSupportedProviders(): string[] {
    return Array.from(this.integrations.keys());
  }
}

// Google Calendar Integration
class GoogleCalendarIntegration implements CalendarIntegration {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async getAvailableSlots(startDate: Date, endDate: Date, duration: number): Promise<CalendarSlot[]> {
    // Implementation would use Google Calendar API
    // For now, return simulated slots
    return this.simulateAvailableSlots(startDate, endDate, duration);
  }

  async createEvent(event: CalendarEventRequest): Promise<string> {
    // Implementation would call Google Calendar API
    return `google_${Date.now()}`;
  }

  async updateEvent(eventId: string, updates: Partial<CalendarEventRequest>): Promise<boolean> {
    return true;
  }

  async deleteEvent(eventId: string): Promise<boolean> {
    return true;
  }

  async getEvent(eventId: string): Promise<CalendarEvent | null> {
    // Implementation would fetch from Google Calendar API
    return null;
  }

  private simulateAvailableSlots(startDate: Date, endDate: Date, duration: number): CalendarSlot[] {
    const slots: CalendarSlot[] = [];
    const current = new Date(startDate);

    while (current < endDate && slots.length < 10) {
      if (current.getDay() !== 0 && current.getDay() !== 6) { // Skip weekends
        const slotStart = new Date(current);
        slotStart.setHours(10, 0, 0, 0); // 10 AM slot

        const slotEnd = new Date(slotStart);
        slotEnd.setMinutes(slotEnd.getMinutes() + duration);

        slots.push({
          start: slotStart.toISOString(),
          end: slotEnd.toISOString(),
          timezone: 'UTC',
          available: true,
          calendar_owner: 'google_calendar'
        });
      }
      current.setDate(current.getDate() + 1);
    }

    return slots;
  }
}

// Outlook Calendar Integration
class OutlookCalendarIntegration implements CalendarIntegration {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async getAvailableSlots(startDate: Date, endDate: Date, duration: number): Promise<CalendarSlot[]> {
    // Implementation would use Microsoft Graph API
    return this.simulateAvailableSlots(startDate, endDate, duration);
  }

  async createEvent(event: CalendarEventRequest): Promise<string> {
    return `outlook_${Date.now()}`;
  }

  async updateEvent(eventId: string, updates: Partial<CalendarEventRequest>): Promise<boolean> {
    return true;
  }

  async deleteEvent(eventId: string): Promise<boolean> {
    return true;
  }

  async getEvent(eventId: string): Promise<CalendarEvent | null> {
    return null;
  }

  private simulateAvailableSlots(startDate: Date, endDate: Date, duration: number): CalendarSlot[] {
    // Similar implementation to Google Calendar
    return [];
  }
}

// CalDAV Integration for generic calendar support
class CalDAVIntegration implements CalendarIntegration {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async getAvailableSlots(startDate: Date, endDate: Date, duration: number): Promise<CalendarSlot[]> {
    // Implementation would use CalDAV protocol
    return [];
  }

  async createEvent(event: CalendarEventRequest): Promise<string> {
    return `caldav_${Date.now()}`;
  }

  async updateEvent(eventId: string, updates: Partial<CalendarEventRequest>): Promise<boolean> {
    return true;
  }

  async deleteEvent(eventId: string): Promise<boolean> {
    return true;
  }

  async getEvent(eventId: string): Promise<CalendarEvent | null> {
    return null;
  }
}

// Email service for sending calendar invites
// TODO: Consider splitting EmailService into smaller, focused classes
class EmailService {
  private env: Env;

  constructor(env: Env) {
    this.env = env;
  }

  async sendCalendarInvite(options: {
    to: string[];
    subject: string;
    icsContent: string;
    meeting: Meeting;
  }): Promise<boolean> {
    try {
      // Implementation would send email with ICS attachment

      // In real implementation, use email service like SendGrid, AWS SES, etc.
      return true;

    } catch (error) {
      return false;
    }
  }
}