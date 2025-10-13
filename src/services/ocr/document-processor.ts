// @ts-nocheck
/**
 * OCR Document Processing Service
 * Extracts structured data from receipts, invoices, and bills
 * Uses Cloudflare AI Workers for OCR
 */

import type { Env } from '../../types/env';

export interface DocumentOCRResult {
  success: boolean;
  document_type: 'invoice' | 'receipt' | 'bill' | 'unknown';
  confidence: number;
  extracted_data: {
    // Common fields
    date?: string;
    total_amount?: number;
    currency?: string;
    vendor_name?: string;
    vendor_address?: string;

    // Invoice-specific
    invoice_number?: string;
    due_date?: string;
    customer_name?: string;

    // Line items
    line_items?: Array<{
      description: string;
      quantity?: number;
      unit_price?: number;
      amount: number;
    }>;

    // Tax information
    tax_amount?: number;
    tax_rate?: number;
    subtotal?: number;

    // Payment details
    payment_method?: string;
    payment_reference?: string;
  };
  raw_text: string;
  processing_time_ms: number;
}

export class DocumentProcessor {
  constructor(private env: Env) {}

  /**
   * Process a document image/PDF and extract structured data
   */
  async processDocument(
    fileBuffer: ArrayBuffer,
    fileType: string,
    businessId: string
  ): Promise<DocumentOCRResult> {
    const startTime = Date.now();

    try {
      // Step 1: Extract text using Cloudflare AI Vision
      const rawText = await this.extractTextFromImage(fileBuffer, fileType);

      // Step 2: Classify document type
      const documentType = await this.classifyDocument(rawText);

      // Step 3: Extract structured data using AI
      const extractedData = await this.extractStructuredData(rawText, documentType);

      // Step 4: Validate and enhance data
      const validatedData = this.validateExtractedData(extractedData);

      // Step 5: Calculate confidence score
      const confidence = this.calculateConfidence(validatedData, rawText);

      const processingTime = Date.now() - startTime;

      return {
        success: true,
        document_type: documentType,
        confidence,
        extracted_data: validatedData,
        raw_text: rawText,
        processing_time_ms: processingTime
      };
    } catch (error) {
      console.error('Document processing error:', error);
      return {
        success: false,
        document_type: 'unknown',
        confidence: 0,
        extracted_data: {},
        raw_text: '',
        processing_time_ms: Date.now() - startTime
      };
    }
  }

  /**
   * Extract text from image using Cloudflare AI
   */
  private async extractTextFromImage(
    fileBuffer: ArrayBuffer,
    fileType: string
  ): Promise<string> {
    try {
      // Use Cloudflare Workers AI for OCR
      // Model: @cf/meta/llama-3.2-11b-vision-instruct
      const response = await this.env.AI.run(
        '@cf/meta/llama-3.2-11b-vision-instruct',
        {
          image: [...new Uint8Array(fileBuffer)],
          prompt: 'Extract all text from this document. Include numbers, dates, amounts, and descriptions. Format the output as plain text.',
          max_tokens: 2048,
        }
      );

      if (response && response.response) {
        return response.response;
      }

      throw new Error('No text extracted from image');
    } catch (error) {
      console.error('OCR extraction error:', error);
      throw error;
    }
  }

  /**
   * Classify document type using AI
   */
  private async classifyDocument(text: string): Promise<'invoice' | 'receipt' | 'bill' | 'unknown'> {
    try {
      const prompt = `Analyze this document text and classify it as one of: invoice, receipt, bill, or unknown.

Document text:
${text}

Respond with ONLY one word: invoice, receipt, bill, or unknown.`;

      const response = await this.env.AI.run('@cf/meta/llama-3-8b-instruct', {
        messages: [
          { role: 'system', content: 'You are a document classification expert.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: 10,
      });

      const classification = response.response?.toLowerCase().trim() as any;

      if (['invoice', 'receipt', 'bill'].includes(classification)) {
        return classification;
      }

      return 'unknown';
    } catch (error) {
      console.error('Classification error:', error);
      return 'unknown';
    }
  }

  /**
   * Extract structured data using AI
   */
  private async extractStructuredData(
    text: string,
    documentType: string
  ): Promise<any> {
    try {
      const prompt = `Extract structured data from this ${documentType} document.

Document text:
${text}

Extract the following information in JSON format:
{
  "date": "YYYY-MM-DD",
  "total_amount": number,
  "currency": "USD/EUR/etc",
  "vendor_name": "string",
  "vendor_address": "string",
  "invoice_number": "string" (if invoice),
  "due_date": "YYYY-MM-DD" (if invoice),
  "customer_name": "string" (if invoice),
  "line_items": [
    {
      "description": "string",
      "quantity": number,
      "unit_price": number,
      "amount": number
    }
  ],
  "tax_amount": number,
  "tax_rate": number,
  "subtotal": number,
  "payment_method": "string",
  "payment_reference": "string"
}

Return ONLY valid JSON. If a field is not found, omit it or set to null.`;

      const response = await this.env.AI.run('@cf/meta/llama-3-8b-instruct', {
        messages: [
          {
            role: 'system',
            content: 'You are a data extraction expert. Always respond with valid JSON only.'
          },
          { role: 'user', content: prompt }
        ],
        max_tokens: 1024,
      });

      // Parse AI response
      let extractedData = {};
      try {
        const jsonMatch = response.response?.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          extractedData = JSON.parse(jsonMatch[0]);
        }
      } catch (parseError) {
        console.error('JSON parse error:', parseError);
      }

      return extractedData;
    } catch (error) {
      console.error('Data extraction error:', error);
      return {};
    }
  }

  /**
   * Validate and clean extracted data
   */
  private validateExtractedData(data: any): any {
    const validated: any = {};

    // Validate and convert date
    if (data.date) {
      const dateMatch = data.date.match(/\d{4}-\d{2}-\d{2}/);
      if (dateMatch) {
        validated.date = dateMatch[0];
      }
    }

    // Validate amounts
    if (data.total_amount && !isNaN(data.total_amount)) {
      validated.total_amount = parseFloat(data.total_amount);
    }

    if (data.tax_amount && !isNaN(data.tax_amount)) {
      validated.tax_amount = parseFloat(data.tax_amount);
    }

    if (data.subtotal && !isNaN(data.subtotal)) {
      validated.subtotal = parseFloat(data.subtotal);
    }

    // Validate currency
    if (data.currency && /^[A-Z]{3}$/.test(data.currency)) {
      validated.currency = data.currency;
    } else {
      validated.currency = 'USD'; // Default
    }

    // Copy string fields
    const stringFields = [
      'vendor_name',
      'vendor_address',
      'invoice_number',
      'customer_name',
      'payment_method',
      'payment_reference'
    ];

    stringFields.forEach(field => {
      if (data[field] && typeof data[field] === 'string') {
        validated[field] = data[field].trim();
      }
    });

    // Validate line items
    if (Array.isArray(data.line_items)) {
      validated.line_items = data.line_items
        .filter((item: any) => item.description && item.amount)
        .map((item: any) => ({
          description: item.description.trim(),
          quantity: item.quantity ? parseFloat(item.quantity) : 1,
          unit_price: item.unit_price ? parseFloat(item.unit_price) : item.amount,
          amount: parseFloat(item.amount)
        }));
    }

    return validated;
  }

  /**
   * Calculate confidence score based on extracted data completeness
   */
  private calculateConfidence(data: any, rawText: string): number {
    let score = 0;
    let maxScore = 0;

    // Critical fields (20 points each)
    const criticalFields = ['total_amount', 'date', 'vendor_name'];
    criticalFields.forEach(field => {
      maxScore += 20;
      if (data[field]) score += 20;
    });

    // Important fields (10 points each)
    const importantFields = ['invoice_number', 'tax_amount', 'subtotal'];
    importantFields.forEach(field => {
      maxScore += 10;
      if (data[field]) score += 10;
    });

    // Line items (30 points)
    maxScore += 30;
    if (data.line_items && data.line_items.length > 0) {
      score += 30;
    }

    // Raw text quality (10 points)
    maxScore += 10;
    if (rawText.length > 100) {
      score += 10;
    }

    return Math.round((score / maxScore) * 100);
  }

  /**
   * Save processed document to database
   */
  async saveProcessedDocument(
    businessId: string,
    userId: string,
    result: DocumentOCRResult,
    originalFilename: string
  ): Promise<string> {
    const documentId = crypto.randomUUID();

    try {
      await this.env.DB.prepare(`
        INSERT INTO processed_documents (
          id, business_id, user_id, document_type, original_filename,
          confidence_score, extracted_data, raw_text, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        documentId,
        businessId,
        userId,
        result.document_type,
        originalFilename,
        result.confidence,
        JSON.stringify(result.extracted_data),
        result.raw_text
      ).run();

      return documentId;
    } catch (error) {
      console.error('Error saving processed document:', error);
      throw error;
    }
  }
}
