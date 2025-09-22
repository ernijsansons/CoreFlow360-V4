import type {
  Meeting,
  Lead,
  Conversation,
  CalendarSlot,
  MeetingType,
  MeetingBookingRequest,
  MeetingAttendee,
  AttendeeRole,
  MeetingTemplate
} from '../types/crm';
import type { Env } from '../types/env';
import { CalendarService, CalendarEventRequest } from './calendar-service';
import { ScheduleNegotiator } from './schedule-negotiator';

export class MeetingBooker {
  private calendarService: CalendarService;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.calendarService = new CalendarService(env);
  }

  /**
   * Book a meeting during an active conversation with AI negotiation
   */
  async bookDuringCall(
    lead: Lead,
    conversation: Conversation,
    meetingType: MeetingType = 'discovery_call',
    options?: {
      duration?: number;
      autoConfirm?: boolean;
      sendInvite?: boolean;
      calendarProvider?: string;
    }
  ): Promise<Meeting | null> {
    try {
      const duration = options?.duration || 30; // Default 30 minutes

      // 1. Check calendar availability
      const slots = await this.getAvailableSlots(lead, duration);

      if (slots.length === 0) {
        throw new Error('No available slots found');
      }

      // 2. AI negotiates time
      const negotiator = new ScheduleNegotiator(slots, lead.timezone || 'UTC', this.env);
      const agreedTime = await negotiator.negotiate(conversation, lead, meetingType);

      if (!agreedTime) {
        throw new Error('Could not negotiate an agreed meeting time');
      }

      // 3. Create calendar event
      const meeting = await this.createCalendarEvent({
        lead,
        slot: agreedTime,
        type: meetingType,
        attendees: await this.buildAttendeeList(lead),
        conversation
      });

      // 4. Send confirmation if requested
      if (options?.sendInvite !== false) {
        await this.sendCalendarInvite(meeting);
      }

      return meeting;

    } catch (error) {
      return null;
    }
  }

  /**
   * Book a meeting with predefined slots (instant booking)
   */
  async bookInstantMeeting(request: MeetingBookingRequest): Promise<Meeting | null> {
    try {
      // Validate the request
      if (!request.lead_id || !request.meeting_type) {
        throw new Error('Invalid booking request: missing required fields');
      }

      let selectedSlot: CalendarSlot;

      if (request.preferred_slots && request.preferred_slots.length > 0) {
        // Use the first preferred slot
        selectedSlot = request.preferred_slots[0];
      } else {
        // Get available slots and pick the best one
        const lead = await this.getLeadById(request.lead_id);
        const slots = await this.getAvailableSlots(lead, request.duration_minutes || 30);

        if (slots.length === 0) {
          throw new Error('No available slots');
        }

        selectedSlot = slots[0]; // Take the first available slot
      }

      // Create the meeting
      const meeting = await this.createMeetingFromSlot(request, selectedSlot);

      // Send calendar invite if requested
      if (request.send_calendar_invite !== false) {
        await this.sendCalendarInvite(meeting);
      }

      return meeting;

    } catch (error) {
      return null;
    }
  }

  /**
   * Get available calendar slots for a lead
   */
  async getAvailableSlots(
    lead: Lead,
    durationMinutes: number = 30,
    daysAhead: number = 14
  ): Promise<CalendarSlot[]> {
    try {
      const startDate = new Date();
      const endDate = new Date();
      endDate.setDate(endDate.getDate() + daysAhead);

      // Get calendar provider for the assigned rep
      const assignedRep = await this.getAssignedRep(lead);
      const calendarProvider = assignedRep?.calendar_provider || 'google';

      // Get business hours for filtering
      const businessHours = await this.getBusinessHours(lead.business_id);

      const slots = await this.calendarService.getAvailableSlots(
        calendarProvider,
        assignedRep?.id || 'default',
        startDate,
        endDate,
        durationMinutes,
        businessHours
      );

      return slots;

    } catch (error) {
      return [];
    }
  }

  /**
   * Create a calendar event and meeting record
   */
  private async createCalendarEvent(options: {
    lead: Lead;
    slot: CalendarSlot;
    type: MeetingType;
    attendees: MeetingAttendee[];
    conversation?: Conversation;
  }): Promise<Meeting> {
    const { lead, slot, type, attendees, conversation } = options;

    // Get meeting template for this type
    const template = await this.getMeetingTemplate(lead.business_id, type);

    // Generate meeting title and description
    const title = template?.name || `${type.replace('_', ' ')} with ${lead.first_name} ${lead.last_name}`;
    const description = this.generateMeetingDescription(lead, type, template);

    // Create calendar event
    const calendarEventRequest: CalendarEventRequest = {
      title,
      description,
      start: slot.start,
      end: slot.end,
      timezone: slot.timezone,
      location: template?.default_location,
      attendees: attendees.map(a => ({
        email: a.email,
        name: a.name,
        required: !a.optional
      })),
      reminders: [
        { method: 'email', minutes: 60 }, // 1 hour before
        { method: 'popup', minutes: 15 }  // 15 minutes before
      ]
    };

    // Get the assigned rep's calendar provider
    const assignedRep = await this.getAssignedRep(lead);
    const calendarProvider = assignedRep?.calendar_provider || 'google';

    const calendarEventId = await this.calendarService.createCalendarEvent(
      calendarProvider,
      assignedRep?.id || 'default',
      calendarEventRequest
    );

    // Create meeting record
    const meeting: Meeting = {
      id: this.generateId(),
      business_id: lead.business_id,
      lead_id: lead.id || '',
      contact_id: lead.contact_id,
      title,
      description,
      meeting_type: type,
      status: 'scheduled',
      scheduled_start: slot.start,
      scheduled_end: slot.end,
      timezone: slot.timezone,
      location: template?.default_location,
      meeting_url: template?.auto_generate_meeting_url ? await this.generateMeetingUrl() : undefined,
      calendar_event_id: calendarEventId || undefined,
      attendees,
      agenda: template?.agenda_template ? this.populateAgendaTemplate(template.agenda_template, lead) : undefined,
      ai_generated_agenda: false,
      booking_source: conversation ? 'ai_conversation' : 'manual_booking',
      booking_method: conversation ? 'ai_negotiated' : 'instant_booking',
      confirmation_sent: false,
      reminder_sent: false,
      no_show: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Save meeting to database
    await this.saveMeeting(meeting);

    return meeting;
  }

  private async createMeetingFromSlot(request: MeetingBookingRequest, slot: CalendarSlot): Promise<Meeting> {
    const lead = await this.getLeadById(request.lead_id);
    const attendees = await this.buildAttendeeList(lead);

    return this.createCalendarEvent({
      lead,
      slot,
      type: request.meeting_type,
      attendees
    });
  }

  /**
   * Send calendar invite to all attendees
   */
  async sendCalendarInvite(meeting: Meeting): Promise<boolean> {
    try {
      const success = await this.calendarService.sendCalendarInvite(meeting);

      if (success) {
        // Update meeting record
        meeting.confirmation_sent = true;
        meeting.updated_at = new Date().toISOString();
        await this.saveMeeting(meeting);
      }

      return success;

    } catch (error) {
      return false;
    }
  }

  /**
   * Cancel a meeting
   */
  async cancelMeeting(meetingId: string, reason?: string): Promise<boolean> {
    try {
      const meeting = await this.getMeetingById(meetingId);
      if (!meeting) {
        throw new Error('Meeting not found');
      }

      // Cancel calendar event if it exists
      if (meeting.calendar_event_id) {
        const assignedRep = await this.getAssignedRepForMeeting(meeting);
        const calendarProvider = assignedRep?.calendar_provider || 'google';

        await this.calendarService.deleteCalendarEvent(
          calendarProvider,
          meeting.calendar_event_id
        );
      }

      // Update meeting status
      meeting.status = 'cancelled';
      meeting.cancelled_at = new Date().toISOString();
      meeting.cancellation_reason = reason;
      meeting.updated_at = new Date().toISOString();

      await this.saveMeeting(meeting);

      return true;

    } catch (error) {
      return false;
    }
  }

  /**
   * Reschedule a meeting
   */
  async rescheduleMeeting(
    meetingId: string,
    newSlot: CalendarSlot,
    reason?: string
  ): Promise<Meeting | null> {
    try {
      const originalMeeting = await this.getMeetingById(meetingId);
      if (!originalMeeting) {
        throw new Error('Meeting not found');
      }

      // Cancel original meeting
      await this.cancelMeeting(meetingId, reason);

      // Create new meeting
      const lead = await this.getLeadById(originalMeeting.lead_id);
      const newMeeting = await this.createCalendarEvent({
        lead,
        slot: newSlot,
        type: originalMeeting.meeting_type,
        attendees: originalMeeting.attendees
      });

      // Link to original meeting
      newMeeting.rescheduled_from = meetingId;
      await this.saveMeeting(newMeeting);

      // Send new calendar invite
      await this.sendCalendarInvite(newMeeting);

      return newMeeting;

    } catch (error) {
      return null;
    }
  }

  /**
   * Build attendee list for a meeting
   */
  private async buildAttendeeList(lead: Lead): Promise<MeetingAttendee[]> {
    const attendees: MeetingAttendee[] = [];

    // Add the lead as an attendee
    attendees.push({
      email: lead.email || '',
      name: `${lead.first_name || ''} ${lead.last_name || ''}`.trim(),
      role: 'lead',
      status: 'pending',
      optional: false
    });

    // Add assigned sales rep
    const assignedRep = await this.getAssignedRep(lead);
    if (assignedRep) {
      attendees.push({
        email: assignedRep.email,
        name: assignedRep.name,
        role: 'sales_rep',
        status: 'accepted',
        optional: false
      });
    }

    return attendees;
  }

  private generateMeetingDescription(lead: Lead, type: MeetingType, template?: MeetingTemplate): string {
    let description = template?.description_template || '';

    if (!description) {
      switch (type) {
        case 'discovery_call':
          description
  = `Discovery call with ${lead.first_name} ${lead.last_name} to understand their needs and challenges.`;
          break;
        case 'demo':
          description = `Product demonstration for ${lead.first_name} ${lead.last_name}.`;
          break;
        case 'consultation':
          description = `Consultation meeting with ${lead.first_name} ${lead.last_name}.`;
          break;
        default:
          description = `Meeting with ${lead.first_name} ${lead.last_name}.`;
      }
    }

    // Replace template variables
    description = description
      .replace(/\{lead_first_name\}/g, lead.first_name || '')
      .replace(/\{lead_last_name\}/g, lead.last_name || '')
      .replace(/\{company_name\}/g, lead.company_name || '');

    return description;
  }

  private populateAgendaTemplate(template: string, lead: Lead): string {
    return template
      .replace(/\{lead_first_name\}/g, lead.first_name || '')
      .replace(/\{lead_last_name\}/g, lead.last_name || '')
      .replace(/\{company_name\}/g, lead.company_name || '');
  }

  private async generateMeetingUrl(): Promise<string> {
    // Generate Zoom, Teams, or other video meeting URL
    // For now, return a placeholder
    return `https://meet.coreflow360.com/room/${this.generateId()}`;
  }

  // Helper methods that would interact with database
  private async getLeadById(leadId: string): Promise<Lead> {
    // Implementation would fetch from database
    return {} as Lead;
  }

  private async getMeetingById(meetingId: string): Promise<Meeting | null> {
    // Implementation would fetch from database
    return null;
  }

  private async getAssignedRep(lead: Lead): Promise<any> {
    // Implementation would fetch assigned sales rep from database
    return {
      id: 'rep_1',
      email: 'rep@company.com',
      name: 'Sales Rep',
      calendar_provider: 'google'
    };
  }

  private async getAssignedRepForMeeting(meeting: Meeting): Promise<any> {
    // Find sales rep in attendees
    const salesRep = meeting.attendees.find(a => a.role === 'sales_rep');
    return salesRep ? { calendar_provider: 'google' } : null;
  }

  private async getMeetingTemplate(businessId: string, meetingType: MeetingType): Promise<MeetingTemplate | null> {
    // Implementation would fetch meeting template from database
    return null;
  }

  private async getBusinessHours(businessId: string): Promise<{ start:
  string; end: string; days: number[] } | undefined> {
    // Implementation would fetch business hours from database
    return {
      start: '09:00',
      end: '17:00',
      days: [1, 2, 3, 4, 5] // Monday to Friday
    };
  }

  private async saveMeeting(meeting: Meeting): Promise<void> {
    // Implementation would save to database
  }

  private generateId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  // Static helper method to detect booking intent in conversations
  static async detectBookingIntent(transcript: string): Promise<{
    hasBookingIntent: boolean;
    confidence: number;
    preferredMeetingType?: MeetingType;
    urgency?: 'immediate' | 'soon' | 'flexible';
  }> {
    return ScheduleNegotiator.detectBookingIntent(transcript);
  }

  // Method to suggest optimal meeting times based on lead behavior
  async suggestOptimalTimes(lead: Lead, meetingType: MeetingType): Promise<CalendarSlot[]> {
    try {
      // Get available slots
      const allSlots = await this.getAvailableSlots(lead);

      // Apply AI scoring to find optimal times based on:
      // - Lead's timezone
      // - Historical meeting preferences
      // - Meeting type requirements
      // - Lead's industry patterns

      const scoredSlots = allSlots.map(slot => ({
        slot,
        score: this.calculateOptimalTimeScore(slot, lead, meetingType)
      })).sort((a, b) => b.score - a.score);

      return scoredSlots.slice(0, 5).map(item => item.slot);

    } catch (error) {
      return [];
    }
  }

  private calculateOptimalTimeScore(slot: CalendarSlot, lead: Lead, meetingType: MeetingType): number {
    let score = 100;

    const slotDate = new Date(slot.start);
    const hour = slotDate.getHours();
    const dayOfWeek = slotDate.getDay();

    // Prefer business hours
    if (hour >= 9 && hour <= 17 && dayOfWeek >= 1 && dayOfWeek <= 5) {
      score += 50;
    }

    // Meeting type preferences
    switch (meetingType) {
      case 'discovery_call':
        // Prefer earlier in the week, morning hours
        if (dayOfWeek >= 1 && dayOfWeek <= 3) score += 20;
        if (hour >= 10 && hour <= 12) score += 15;
        break;
      case 'demo':
        // Prefer mid-week, afternoon
        if (dayOfWeek >= 2 && dayOfWeek <= 4) score += 20;
        if (hour >= 14 && hour <= 16) score += 15;
        break;
      case 'closing_call':
        // Prefer end of week, late morning
        if (dayOfWeek >= 4 && dayOfWeek <= 5) score += 20;
        if (hour >= 11 && hour <= 13) score += 15;
        break;
    }

    // Industry-specific preferences could be added here
    // Lead timezone considerations could be added here

    return score;
  }
}