// @ts-nocheck
/**
 * Document Processing API Routes
 * Handles OCR, upload, and document management
 */

import { Hono } from 'hono';
import type { Env } from '../types/env';
import { DocumentProcessor } from '../services/ocr/document-processor';
import { authenticate } from '../middleware/auth';
import { Logger } from "../shared/logger";
const logger = new Logger({ component: "routes-documents" });



const documents = new Hono<{ Bindings: Env }>();

// Apply authentication to all routes
documents.use('*', authenticate);

/**
 * POST /api/documents/upload
 * Upload and process a document (receipt, invoice, bill)
 */
documents.post('/upload', async (c) => {
  try {
    const { businessId, userId } = c.get('auth');

    // Get form data
    const formData = await c.req.formData();
    const file = formData.get('file') as File;
    const documentType = formData.get('type') as string; // Optional hint
    void documentType;

    if (!file) {
      return c.json({ success: false, error: 'No file provided' }, 400);
    }

    // Validate file type
    const allowedTypes = [
      'image/jpeg',
      'image/png',
      'image/jpg',
      'application/pdf',
      'image/webp'
    ];

    if (!allowedTypes.includes(file.type)) {
      return c.json({
        success: false,
        error: 'Invalid file type. Allowed: JPG, PNG, PDF, WebP'
      }, 400);
    }

    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      return c.json({
        success: false,
        error: 'File too large. Maximum size: 10MB'
      }, 400);
    }

    // Convert file to buffer
    const fileBuffer = await file.arrayBuffer();

    // Process document with OCR
    const processor = new DocumentProcessor(c.env);
    const result = await processor.processDocument(
      fileBuffer,
      file.type,
      businessId
    );

    if (!result.success) {
      return c.json({
        success: false,
        error: 'Failed to process document'
      }, 500);
    }

    // Save to R2 storage
    const fileKey = `documents/${businessId}/${Date.now()}-${file.name}`;
    await c.env.R2_DOCUMENTS.put(fileKey, fileBuffer, {
      httpMetadata: {
        contentType: file.type
      },
      customMetadata: {
        business_id: businessId,
        user_id: userId,
        document_type: result.document_type,
        original_filename: file.name
      }
    });

    // Save processed document to database
    const documentId = await processor.saveProcessedDocument(
      businessId,
      userId,
      result,
      file.name
    );

    // Return processed result
    return c.json({
      success: true,
      data: {
        document_id: documentId,
        document_type: result.document_type,
        confidence: result.confidence,
        extracted_data: result.extracted_data,
        file_url: `/api/documents/${documentId}/file`,
        processing_time_ms: result.processing_time_ms
      }
    }, 201);
  } catch (error) {
    logger.error('Document upload error:', error);
    return c.json({
      success: false,
      error: 'Failed to upload and process document'
    }, 500);
  }
});

/**
 * GET /api/documents
 * List processed documents
 */
documents.get('/', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { type, limit = '50', offset = '0' } = c.req.query();

    let query = `
      SELECT
        id, document_type, original_filename, confidence_score,
        extracted_data, created_at
      FROM processed_documents
      WHERE business_id = ?
    `;

    const params: any[] = [businessId];

    if (type) {
      query += ` AND document_type = ?`;
      params.push(type);
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await c.env.DB.prepare(query)
      .bind(...params)
      .all();

    // Parse extracted_data JSON
    const documents = result.results.map((doc: any) => ({
      ...doc,
      extracted_data: JSON.parse(doc.extracted_data)
    }));

    return c.json({
      success: true,
      data: {
        documents,
        total: result.results.length,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
  } catch (error) {
    logger.error('List documents error:', error);
    return c.json({
      success: false,
      error: 'Failed to list documents'
    }, 500);
  }
});

/**
 * GET /api/documents/:id
 * Get document details
 */
documents.get('/:id', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();

    const result = await c.env.DB.prepare(`
      SELECT
        id, document_type, original_filename, confidence_score,
        extracted_data, raw_text, created_at, user_id
      FROM processed_documents
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).first();

    if (!result) {
      return c.json({
        success: false,
        error: 'Document not found'
      }, 404);
    }

    return c.json({
      success: true,
      data: {
        ...result,
        extracted_data: JSON.parse(result.extracted_data as string)
      }
    });
  } catch (error) {
    logger.error('Get document error:', error);
    return c.json({
      success: false,
      error: 'Failed to get document'
    }, 500);
  }
});

/**
 * GET /api/documents/:id/file
 * Download original document file
 */
documents.get('/:id/file', async (c) => {
  try {
    const { businessId } = c.get('auth');
    const { id } = c.req.param();

    // Get document metadata
    const doc = await c.env.DB.prepare(`
      SELECT original_filename
      FROM processed_documents
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).first();

    if (!doc) {
      return c.json({
        success: false,
        error: 'Document not found'
      }, 404);
    }

    // Find file in R2
    const objects = await c.env.R2_DOCUMENTS.list({
      prefix: `documents/${businessId}/`
    });

    const fileObj = objects.objects.find(obj =>
      obj.key.endsWith(doc.original_filename as string)
    );

    if (!fileObj) {
      return c.json({
        success: false,
        error: 'File not found in storage'
      }, 404);
    }

    // Get file from R2
    const file = await c.env.R2_DOCUMENTS.get(fileObj.key);

    if (!file) {
      return c.json({
        success: false,
        error: 'File not found'
      }, 404);
    }

    // Return file
    return new Response(file.body, {
      headers: {
        'Content-Type': file.httpMetadata?.contentType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${doc.original_filename}"`,
      }
    });
  } catch (error) {
    logger.error('Download file error:', error);
    return c.json({
      success: false,
      error: 'Failed to download file'
    }, 500);
  }
});

/**
 * POST /api/documents/:id/create-invoice
 * Create invoice from processed document
 */
documents.post('/:id/create-invoice', async (c) => {
  try {
    const { businessId, userId } = c.get('auth');
    const { id } = c.req.param();

    // Get processed document
    const doc = await c.env.DB.prepare(`
      SELECT extracted_data, document_type
      FROM processed_documents
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).first();

    if (!doc) {
      return c.json({
        success: false,
        error: 'Document not found'
      }, 404);
    }

    if (doc.document_type !== 'invoice') {
      return c.json({
        success: false,
        error: 'Document is not an invoice'
      }, 400);
    }

    const data = JSON.parse(doc.extracted_data as string);

    // Create invoice in database
    const invoiceId = crypto.randomUUID();

    await c.env.DB.prepare(`
      INSERT INTO invoices (
        id, business_id, invoice_number, customer_name,
        issue_date, due_date, subtotal, tax_amount, total,
        currency, status, source_document_id, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, datetime('now'))
    `).bind(
      invoiceId,
      businessId,
      data.invoice_number || `INV-${Date.now()}`,
      data.customer_name || 'Unknown Customer',
      data.date || new Date().toISOString().split('T')[0],
      data.due_date || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      data.subtotal || 0,
      data.tax_amount || 0,
      data.total_amount || 0,
      data.currency || 'USD',
      id,
      userId
    ).run();

    // Create line items
    if (data.line_items && Array.isArray(data.line_items)) {
      for (const item of data.line_items) {
        await c.env.DB.prepare(`
          INSERT INTO invoice_items (
            id, invoice_id, description, quantity, unit_price, amount, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        `).bind(
          crypto.randomUUID(),
          invoiceId,
          item.description,
          item.quantity || 1,
          item.unit_price || item.amount,
          item.amount
        ).run();
      }
    }

    return c.json({
      success: true,
      data: {
        invoice_id: invoiceId,
        message: 'Invoice created successfully from document'
      }
    });
  } catch (error) {
    logger.error('Create invoice from document error:', error);
    return c.json({
      success: false,
      error: 'Failed to create invoice'
    }, 500);
  }
});

/**
 * POST /api/documents/:id/create-expense
 * Create expense from processed document (receipt/bill)
 */
documents.post('/:id/create-expense', async (c) => {
  try {
    const { businessId, userId } = c.get('auth');
    const { id } = c.req.param();
    const body = await c.req.json();

    // Get processed document
    const doc = await c.env.DB.prepare(`
      SELECT extracted_data, document_type
      FROM processed_documents
      WHERE id = ? AND business_id = ?
    `).bind(id, businessId).first();

    if (!doc) {
      return c.json({
        success: false,
        error: 'Document not found'
      }, 404);
    }

    const data = JSON.parse(doc.extracted_data as string);

    // Create expense
    const expenseId = crypto.randomUUID();

    await c.env.DB.prepare(`
      INSERT INTO expenses (
        id, business_id, amount, currency, vendor_name,
        description, category, expense_date, payment_method,
        status, source_document_id, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, datetime('now'))
    `).bind(
      expenseId,
      businessId,
      data.total_amount || 0,
      data.currency || 'USD',
      data.vendor_name || 'Unknown Vendor',
      body.description || 'Expense from document',
      body.category || 'uncategorized',
      data.date || new Date().toISOString().split('T')[0],
      data.payment_method || 'unknown',
      id,
      userId
    ).run();

    return c.json({
      success: true,
      data: {
        expense_id: expenseId,
        message: 'Expense created successfully from document'
      }
    });
  } catch (error) {
    logger.error('Create expense from document error:', error);
    return c.json({
      success: false,
      error: 'Failed to create expense'
    }, 500);
  }
});

export default documents;
