/**
 * Type-safe API response schemas for external integrations
 * Uses Zod for runtime validation
 */

import { z } from 'zod';

/**
 * Gmail API Response Schemas
 */
export const GmailTokenResponseSchema = z.object({
  access_token: z.string(),
  expires_in: z.number(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
  token_type: z.string().optional(),
});

export type GmailTokenResponse = z.infer<typeof GmailTokenResponseSchema>;

export const GmailMessageSchema = z.object({
  id: z.string(),
  threadId: z.string(),
  labelIds: z.array(z.string()).optional(),
  snippet: z.string().optional(),
  payload: z.any().optional(),
  internalDate: z.string().optional(),
});

export const GmailMessagesListResponseSchema = z.object({
  messages: z.array(GmailMessageSchema).optional(),
  nextPageToken: z.string().optional(),
  resultSizeEstimate: z.number().optional(),
  historyId: z.string().optional(),
});

export type GmailMessagesListResponse = z.infer<typeof GmailMessagesListResponseSchema>;

/**
 * Outlook API Response Schemas
 */
export const OutlookTokenResponseSchema = z.object({
  access_token: z.string(),
  expires_in: z.number(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
  token_type: z.string().optional(),
  id_token: z.string().optional(),
});

export type OutlookTokenResponse = z.infer<typeof OutlookTokenResponseSchema>;

export const GraphMessageSchema = z.object({
  id: z.string(),
  subject: z.string().optional(),
  bodyPreview: z.string().optional(),
  body: z.object({
    contentType: z.enum(['text', 'html']).optional(),
    content: z.string().optional(),
  }).optional(),
  from: z.object({
    emailAddress: z.object({
      name: z.string().optional(),
      address: z.string(),
    }),
  }).optional(),
  toRecipients: z.array(z.any()).optional(),
  ccRecipients: z.array(z.any()).optional(),
  bccRecipients: z.array(z.any()).optional(),
  sentDateTime: z.string().optional(),
  receivedDateTime: z.string().optional(),
  conversationId: z.string().optional(),
  isRead: z.boolean().optional(),
  hasAttachments: z.boolean().optional(),
  importance: z.enum(['low', 'normal', 'high']).optional(),
});

export const OutlookMessagesResponseSchema = z.object({
  value: z.array(GraphMessageSchema),
  '@odata.nextLink': z.string().optional(),
  '@odata.count': z.number().optional(),
});

export type OutlookMessagesResponse = z.infer<typeof OutlookMessagesResponseSchema>;

export const OutlookEventsResponseSchema = z.object({
  value: z.array(z.any()),
  '@odata.nextLink': z.string().optional(),
});

/**
 * Slack API Response Schemas
 */
export const SlackUserInfoResponseSchema = z.object({
  ok: z.boolean(),
  user: z.object({
    id: z.string(),
    name: z.string(),
    real_name: z.string().optional(),
    profile: z.object({
      email: z.string().optional(),
      display_name: z.string().optional(),
    }).optional(),
  }).optional(),
  error: z.string().optional(),
});

export type SlackUserInfoResponse = z.infer<typeof SlackUserInfoResponseSchema>;

export const SlackChannelInfoResponseSchema = z.object({
  ok: z.boolean(),
  channel: z.object({
    id: z.string(),
    name: z.string(),
    is_channel: z.boolean().optional(),
    is_group: z.boolean().optional(),
    is_im: z.boolean().optional(),
    is_private: z.boolean().optional(),
  }).optional(),
  error: z.string().optional(),
});

export type SlackChannelInfoResponse = z.infer<typeof SlackChannelInfoResponseSchema>;

export const SlackConversationHistoryResponseSchema = z.object({
  ok: z.boolean(),
  messages: z.array(z.any()).optional(),
  error: z.string().optional(),
});

export type SlackConversationHistoryResponse = z.infer<typeof SlackConversationHistoryResponseSchema>;

export const SlackMessageEventSchema = z.object({
  type: z.literal('message'),
  user: z.string().optional(),
  text: z.string().optional(),
  ts: z.string().optional(),
  channel: z.string().optional(),
  thread_ts: z.string().optional(),
  subtype: z.string().optional(), // Added missing subtype
  message: z.any().optional(),
});

export type SlackMessageEvent = z.infer<typeof SlackMessageEventSchema>;

/**
 * Generic error response
 */
export const APIErrorResponseSchema = z.object({
  error: z.string(),
  error_description: z.string().optional(),
  code: z.number().optional(),
  message: z.string().optional(),
});

export type APIErrorResponse = z.infer<typeof APIErrorResponseSchema>;

/**
 * Type guard utility function
 */
export function validateAPIResponse<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  errorMessage: string = 'Invalid API response'
): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`${errorMessage}: ${error.errors.map(e => e.message).join(', ')}`);
    }
    throw new Error(errorMessage);
  }
}

/**
 * Safe parse utility (returns undefined on error)
 */
export function safeParseAPIResponse<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): T | undefined {
  const result = schema.safeParse(data);
  return result.success ? result.data : undefined;
}
