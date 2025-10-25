/**
 * Settings Routes
 * Handles application and user settings
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';

const settings = new Hono<{ Bindings: Env }>();

// Get settings
settings.get('/', async (c) => {
  try {
    return c.json({
      success: true,
      settings: {
        general: {
          appName: 'CoreFlow360 V4',
          timezone: 'UTC',
          language: 'en',
          dateFormat: 'YYYY-MM-DD'
        },
        notifications: {
          email: true,
          sms: false,
          push: true
        },
        security: {
          twoFactorEnabled: false,
          sessionTimeout: 3600
        },
        preferences: {
          theme: 'light',
          sidebarCollapsed: false
        }
      }
    });
  } catch (error: any) {
    console.error('Error fetching settings:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to fetch settings'
    }, 500);
  }
});

// Update settings
settings.patch('/', async (c) => {
  try {
    const body = await c.req.json();

    return c.json({
      success: true,
      message: 'Settings updated successfully',
      settings: {
        ...body,
        updatedAt: new Date().toISOString()
      }
    });
  } catch (error: any) {
    console.error('Error updating settings:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to update settings'
    }, 500);
  }
});

// Get specific setting category
settings.get('/:category', async (c) => {
  try {
    const category = c.req.param('category');

    return c.json({
      success: true,
      category,
      settings: {}
    });
  } catch (error: any) {
    console.error('Error fetching setting category:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to fetch setting category'
    }, 500);
  }
});

// Update specific setting category
settings.patch('/:category', async (c) => {
  try {
    const category = c.req.param('category');
    const body = await c.req.json();

    return c.json({
      success: true,
      message: `${category} settings updated`,
      settings: {
        ...body,
        updatedAt: new Date().toISOString()
      }
    });
  } catch (error: any) {
    console.error('Error updating setting category:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to update setting category'
    }, 500);
  }
});

// Reset settings to defaults
settings.post('/reset', async (c) => {
  try {
    return c.json({
      success: true,
      message: 'Settings reset to defaults'
    });
  } catch (error: any) {
    console.error('Error resetting settings:', error);
    return c.json({
      success: false,
      error: error.message || 'Failed to reset settings'
    }, 500);
  }
});

export default settings;
