import { Pipeline, PipelineStage, Transformation, ErrorHandlingStrategy } from '../../types/migration';

interface TransformationRules {
  globalRules: Transformation[];
  fieldRules: Map<string, Transformation[]>;
  validationRules: ValidationRule[];
  enrichmentRules: EnrichmentRule[];
}

interface ValidationRule {
  id: string;
  field: string;
  type: 'REQUIRED' | 'RANGE' | 'PATTERN' | 'CUSTOM';
  parameters: Record<string, any>;
  errorMessage: string;
}

interface EnrichmentRule {
  id: string;
  field: string;
  type: 'LOOKUP' | 'CALCULATION' | 'GEOCODING' | 'CURRENCY_CONVERSION';
  source: string;
  parameters: Record<string, any>;
}

interface TransformationContext {
  record: Record<string, any>;
  metadata: Record<string, any>;
  batchId: string;
  index: number;
  lookup: LookupService;
  env: any;
}

interface CleaningConfig {
  trimWhitespace: boolean;
  normalizeCase: boolean;
  fixEncoding: boolean;
  handleNulls: 'skip' | 'default' | 'smart-defaults' | 'error';
  removeSpecialChars: boolean;
  standardizeFormats: boolean;
}

interface TypeConversionConfig {
  dateFormat: string | 'auto-detect';
  numberFormat: 'locale-aware' | 'standard';
  booleanMapping: 'strict' | 'fuzzy-match';
  stringEncoding: 'utf8' | 'latin1' | 'ascii';
  timezone: string;
}

interface BusinessLogicConfig {
  calculateDerived: boolean;
  applyDefaults: boolean;
  validateConstraints: boolean;
  customRules: string[];
}

interface EnrichmentConfig {
  geocoding: boolean;
  currencyConversion: boolean;
  lookupTables: Map<string, any[]>;
  externalAPIs: Map<string, string>;
}

// TODO: Consider splitting LookupService into smaller, focused classes
class LookupService {
  private tables: Map<string, any[]> = new Map();
  private cache: Map<string, any> = new Map();

  constructor(lookupTables: Map<string, any[]>) {
    this.tables = lookupTables;
  }

  async lookup(tableName: string, key: string, value: any): Promise<any> {
    const cacheKey = `${tableName}:${key}:${value}`;

    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey);
    }

    const table = this.tables.get(tableName);
    if (!table) return null;

    const result = table.find(row => row[key] === value);
    this.cache.set(cacheKey, result);

    return result;
  }

  async reverseLookup(tableName: string, targetKey: string, targetValue: any): Promise<any> {
    const table = this.tables.get(tableName);
    if (!table) return null;

    return table.find(row => row[targetKey] === targetValue);
  }
}

export class TransformationEngine {
  private env: any;
  private lookupService: LookupService;

  constructor(env: any) {
    this.env = env;
    this.lookupService = new LookupService(new Map());
  }

  async buildPipeline(rules: TransformationRules): Promise<Pipeline> {
    const stages: PipelineStage[] = [
      {
        id: 'cleaning',
        name: 'Data Cleaning',
        type: 'CLEANING',
        order: 1,
        enabled: true,
        configuration: {
          trimWhitespace: true,
          normalizeCase: true,
          fixEncoding: true,
          handleNulls: 'smart-defaults'
        },
        outputs: ['cleaned_data']
      },
      {
        id: 'type_conversion',
        name: 'Type Conversion',
        type: 'TRANSFORMATION',
        order: 2,
        enabled: true,
        configuration: {
          dateFormat: 'auto-detect',
          numberFormat: 'locale-aware',
          booleanMapping: 'fuzzy-match'
        },
        outputs: ['typed_data']
      },
      {
        id: 'validation',
        name: 'Data Validation',
        type: 'VALIDATION',
        order: 3,
        enabled: true,
        configuration: {
          rules: rules.validationRules
        },
        outputs: ['validated_data']
      },
      {
        id: 'business_logic',
        name: 'Business Logic',
        type: 'TRANSFORMATION',
        order: 4,
        enabled: true,
        configuration: {
          calculateDerived: true,
          applyDefaults: true,
          validateConstraints: true
        },
        outputs: ['processed_data']
      },
      {
        id: 'enrichment',
        name: 'Data Enrichment',
        type: 'ENRICHMENT',
        order: 5,
        enabled: true,
        configuration: {
          geocoding: true,
          currencyConversion: true,
          lookupTables: this.getLookupTables()
        },
        outputs: ['enriched_data']
      }
    ];

    return {
      id: crypto.randomUUID(),
      name: 'Migration Pipeline',
      stages,
      parallelism: 4,
      errorHandling: {
        onError: 'RETRY',
        retryAttempts: 3,
        retryDelay: 1000,
        logLevel: 'ERROR'
      }
    };
  }

  async processRecord(
    record: Record<string, any>,
    pipeline: Pipeline,
    context: TransformationContext
  ): Promise<Record<string, any>> {
    let processedRecord = { ...record };

    // Sort stages by order
    const sortedStages = pipeline.stages
      .filter((stage: any) => stage.enabled)
      .sort((a, b) => a.order - b.order);

    // Process through each stage
    for (const stage of sortedStages) {
      try {
        processedRecord = await this.processStage(stage, processedRecord, context);
      } catch (error: any) {
        processedRecord = await this.handleStageError(stage, error as Error, processedRecord, pipeline.errorHandling);
      }
    }

    return processedRecord;
  }

  private async processStage(
    stage: PipelineStage,
    record: Record<string, any>,
    context: TransformationContext
  ): Promise<Record<string, any>> {
    switch (stage.type) {
      case 'CLEANING':
        return this.applyCleaningStage(record, stage.configuration as CleaningConfig);
      case 'TRANSFORMATION':
        return this.applyTransformationStage(record, stage, context);
      case 'VALIDATION':
        return this.applyValidationStage(record, stage.configuration);
      case 'ENRICHMENT':
        return this.applyEnrichmentStage(record, stage.configuration as EnrichmentConfig, context);
      case 'CUSTOM':
        return this.applyCustomStage(record, stage.configuration, context);
      default:
        return record;
    }
  }

  private async applyCleaningStage(record: Record<string, any>, config: CleaningConfig): Promise<Record<string, any>> {
    const cleaned: Record<string, any> = {};

    for (const [key, value] of Object.entries(record)) {
      let cleanedValue = value;

      if (typeof value === 'string') {
        // Trim whitespace
        if (config.trimWhitespace) {
          cleanedValue = cleanedValue.trim();
        }

        // Normalize case
        if (config.normalizeCase) {
          cleanedValue = cleanedValue.toLowerCase();
        }

        // Fix encoding issues
        if (config.fixEncoding) {
          cleanedValue = this.fixEncoding(cleanedValue);
        }

        // Remove special characters
        if (config.removeSpecialChars) {
          cleanedValue = cleanedValue.replace(/[^\w\s@.-]/g, '');
        }

        // Standardize formats
        if (config.standardizeFormats) {
          cleanedValue = this.standardizeFormat(key, cleanedValue);
        }
      }

      // Handle null values
      if (cleanedValue === null || cleanedValue === undefined || cleanedValue === '') {
        cleanedValue = this.handleNullValue(key, config.handleNulls);
      }

      cleaned[key] = cleanedValue;
    }

    return cleaned;
  }

  private async applyTransformationStage(
    record: Record<string, any>,
    stage: PipelineStage,
    context: TransformationContext
  ): Promise<Record<string, any>> {
    const transformed: Record<string, any> = { ...record };
    const config = stage.configuration;

    for (const [key, value] of Object.entries(record)) {
      // Apply type conversions based on stage name
      if (stage.name === 'Type Conversion') {
        transformed[key] = await this.convertType(key, value, config as TypeConversionConfig);
      } else if (stage.name === 'Business Logic') {
        transformed[key] = await this.applyBusinessLogic(key, value, transformed, config as BusinessLogicConfig);
      }
    }

    // Calculate derived fields
    if (config.calculateDerived) {
      const derivedFields = await this.calculateDerivedFields(transformed);
      Object.assign(transformed, derivedFields);
    }

    return transformed;
  }

  private async applyValidationStage(record: Record<string, any>, config: any): Promise<Record<string, any>> {
    const rules = config.rules as ValidationRule[];
    const errors: string[] = [];

    for (const rule of rules) {
      const isValid = await this.validateField(record, rule);
      if (!isValid) {
        errors.push(`${rule.field}: ${rule.errorMessage}`);
      }
    }

    if (errors.length > 0) {
      throw new Error(`Validation failed: ${errors.join(', ')}`);
    }

    return record;
  }

  private async applyEnrichmentStage(
    record: Record<string, any>,
    config: EnrichmentConfig,
    context: TransformationContext
  ): Promise<Record<string, any>> {
    const enriched: Record<string, any> = { ...record };

    // Geocoding
    if (config.geocoding && record.address) {
      const geoData = await this.geocodeAddress(record.address);
      if (geoData) {
        enriched.latitude = geoData.latitude;
        enriched.longitude = geoData.longitude;
        enriched.country = geoData.country;
        enriched.timezone = geoData.timezone;
      }
    }

    // Currency conversion
    if (config.currencyConversion && record.amount && record.currency) {
      const convertedAmount = await this.convertCurrency(record.amount, record.currency, 'USD');
      enriched.amount_usd = convertedAmount;
    }

    // Lookup table enrichment
    for (const [tableName, lookupTable] of config.lookupTables) {
      const enrichmentData = await this.performLookupEnrichment(record, tableName, lookupTable);
      Object.assign(enriched, enrichmentData);
    }

    // External API enrichment
    for (const [apiName, apiUrl] of config.externalAPIs) {
      try {
        const apiData = await this.enrichFromExternalAPI(record, apiName, apiUrl);
        Object.assign(enriched, apiData);
      } catch (error: any) {
      }
    }

    return enriched;
  }

  private async applyCustomStage(
    record: Record<string, any>,
    config: any,
    context: TransformationContext
  ): Promise<Record<string, any>> {
    // Execute custom JavaScript transformation
    if (config.code) {
      try {
        const func = new Function('record', 'context', config.code);
        return func(record, context) || record;
      } catch (error: any) {
        return record;
      }
    }

    return record;
  }

  private async convertType(key: string, value: any, config: TypeConversionConfig): Promise<any> {
    if (value === null || value === undefined) return value;

    // Date conversion
    if (this.shouldConvertToDate(key, value)) {
      return this.convertToDate(value, config.dateFormat, config.timezone);
    }

    // Number conversion
    if (this.shouldConvertToNumber(key, value)) {
      return this.convertToNumber(value, config.numberFormat);
    }

    // Boolean conversion
    if (this.shouldConvertToBoolean(key, value)) {
      return this.convertToBoolean(value, config.booleanMapping);
    }

    return value;
  }

  private async applyBusinessLogic(
    key: string,
    value: any,
    record: Record<string, any>,
    config: BusinessLogicConfig
  ): Promise<any> {
    // Apply default values
    if (config.applyDefaults && (value === null || value === undefined)) {
      return this.getDefaultValue(key);
    }

    // Validate business constraints
    if (config.validateConstraints) {
      this.validateBusinessConstraints(key, value, record);
    }

    return value;
  }

  private async calculateDerivedFields(record: Record<string, any>): Promise<Record<string, any>> {
    const derived: Record<string, any> = {};

    // Calculate full name from first and last name
    if (record.first_name && record.last_name) {
      derived.full_name = `${record.first_name} ${record.last_name}`;
    }

    // Calculate age from birth date
    if (record.birth_date) {
      const birthDate = new Date(record.birth_date);
      const today = new Date();
      derived.age = Math.floor((today.getTime() - birthDate.getTime()) / (365.25 * 24 * 60 * 60 * 1000));
    }

    // Calculate total from line items
    if (record.line_items && Array.isArray(record.line_items)) {
      derived.total_amount = record.line_items.reduce((sum: number, item: any) => {
        return sum + (item.quantity * item.price);
      }, 0);
    }

    // Generate display name
    if (record.company_name || record.full_name || record.email) {
      derived.display_name = record.company_name || record.full_name || record.email;
    }

    return derived;
  }

  private async validateField(record: Record<string, any>, rule: ValidationRule): Promise<boolean> {
    const value = record[rule.field];

    switch (rule.type) {
      case 'REQUIRED':
        return value !== null && value !== undefined && value !== '';

      case 'RANGE':
        const min = rule.parameters.min;
        const max = rule.parameters.max;
        const numValue = Number(value);
        return !isNaN(numValue) && numValue >= min && numValue <= max;

      case 'PATTERN':
        const pattern = new RegExp(rule.parameters.pattern);
        return pattern.test(String(value));

      case 'CUSTOM':
        try {
          const func = new Function('value', 'record', rule.parameters.code);
          return func(value, record);
        } catch (error: any) {
          return false;
        }

      default:
        return true;
    }
  }

  private async geocodeAddress(address: string): Promise<any> {
    if (!this.env.GEOCODING_API_KEY) return null;

    try {
    
   const response = await fetch(`https://api.mapbox.com/geocoding/v5/mapbox.places/${encodeURIComponent(address)}.json?access_token=${this.env.GEOCODING_API_KEY}`);
      const data = await response.json();

      if (data.features && data.features.length > 0) {
        const feature = data.features[0];
        return {
          latitude: feature.center[1],
          longitude: feature.center[0],
          country: this.extractCountry(feature.context),
          timezone: this.getTimezoneFromCoordinates(feature.center[1], feature.center[0])
        };
      }
    } catch (error: any) {
    }

    return null;
  }

  private async convertCurrency(amount: number, fromCurrency: string, toCurrency: string): Promise<number> {
    if (fromCurrency === toCurrency) return amount;

    try {
      // Use a currency conversion API
      const response = await fetch(`https://api.exchangerate-api.com/v4/latest/${fromCurrency}`);
      const data = await response.json();

      if (data.rates && data.rates[toCurrency]) {
        return amount * data.rates[toCurrency];
      }
    } catch (error: any) {
    }

    return amount; // Return original amount if conversion fails
  }

  private async performLookupEnrichment(record: Record<string, any>,
  tableName: string, lookupTable: any[]): Promise<Record<string, any>> {
    const enrichment: Record<string, any> = {};

    // Look for matching keys in the record
    for (const [key, value] of Object.entries(record)) {
      const lookupResult = await this.lookupService.lookup(tableName, key, value);
      if (lookupResult) {
        // Add enriched fields with prefix to avoid conflicts
        for (const [enrichKey, enrichValue] of Object.entries(lookupResult)) {
          if (enrichKey !== key) { // Don't overwrite the lookup key
            enrichment[`${tableName}_${enrichKey}`] = enrichValue;
          }
        }
      }
    }

    return enrichment;
  }

  private async enrichFromExternalAPI(record: Record<string, any>,
  apiName: string, apiUrl: string): Promise<Record<string, any>> {
    const enrichment: Record<string, any> = {};

    try {
      // Replace placeholders in API URL
      let finalUrl = apiUrl;
      for (const [key, value] of Object.entries(record)) {
        finalUrl = finalUrl.replace(`{${key}}`, encodeURIComponent(String(value)));
      }

      const response = await fetch(finalUrl, {
        headers: {
          'Authorization': `Bearer ${this.env[`${apiName.toUpperCase()}_API_KEY`]}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        // Prefix external data to avoid conflicts
        for (const [key, value] of Object.entries(data)) {
          enrichment[`${apiName}_${key}`] = value;
        }
      }
    } catch (error: any) {
    }

    return enrichment;
  }

  private async handleStageError(
    stage: PipelineStage,
    error: Error,
    record: Record<string, any>,
    errorHandling: ErrorHandlingStrategy
  ): Promise<Record<string, any>> {

    switch (errorHandling.onError) {
      case 'SKIP':
        return record; // Return original record

      case 'FALLBACK':
        return { ...record, [`${stage.id}_error`]: error.message };

      case 'RETRY':
        // This would be handled at a higher level with retry logic
        throw error;

      case 'FAIL':
      default:
        throw error;
    }
  }

  // Utility methods
  private fixEncoding(text: string): string {
    // Fix common encoding issues
    return text
      .replace(/â€™/g, "'")
      .replace(/â€œ/g, '"')
      .replace(/â€/g, '"')
      .replace(/â€"/g, '—')
      .replace(/Â/g, '');
  }

  private standardizeFormat(fieldName: string, value: string): string {
    const field = fieldName.toLowerCase();

    // Phone number standardization
    if (field.includes('phone') || field.includes('tel')) {
      return value.replace(/[^\d+]/g, '');
    }

    // Email standardization
    if (field.includes('email')) {
      return value.toLowerCase().trim();
    }

    // Postal code standardization
    if (field.includes('zip') || field.includes('postal')) {
      return value.replace(/\s/g, '').toUpperCase();
    }

    return value;
  }

  private handleNullValue(fieldName: string, strategy: string): any {
    switch (strategy) {
      case 'skip':
        return null;
      case 'default':
        return this.getDefaultValue(fieldName);
      case 'smart-defaults':
        return this.getSmartDefault(fieldName);
      case 'error':
        throw new Error(`Null value not allowed for field: ${fieldName}`);
      default:
        return null;
    }
  }

  private getDefaultValue(fieldName: string): any {
    const field = fieldName.toLowerCase();

    if (field.includes('date')) return new Date().toISOString();
    if (field.includes('count') || field.includes('number') || field.includes('amount')) return 0;
    if (field.includes('flag') || field.includes('enabled') || field.includes('active')) return false;
    if (field.includes('name') || field.includes('title')) return 'Unknown';
    if (field.includes('email')) return 'noemail@example.com';

    return '';
  }

  private getSmartDefault(fieldName: string): any {
    // More intelligent defaults based on field semantics
    const field = fieldName.toLowerCase();

    if (field === 'created_at' || field === 'updated_at') return new Date().toISOString();
    if (field === 'status') return 'active';
    if (field === 'type') return 'standard';
    if (field === 'category') return 'uncategorized';
    if (field.includes('priority')) return 'medium';

    return this.getDefaultValue(fieldName);
  }

  private shouldConvertToDate(fieldName: string, value: any): boolean {
    const field = fieldName.toLowerCase();
    return field.includes('date') || field.includes('time') || field.includes('created') || field.includes('updated');
  }

  private shouldConvertToNumber(fieldName: string, value: any): boolean {
    const field = fieldName.toLowerCase();
    return (field.includes('amount') || field.includes('price') || field.includes('count') || field.includes('number'))
           && typeof value === 'string' && !isNaN(Number(value));
  }

  private shouldConvertToBoolean(fieldName: string, value: any): boolean {
    const field = fieldName.toLowerCase();
    return field.includes('flag') || field.includes('enabled') || field.includes('active') || field.includes('is_');
  }

  private convertToDate(value: any, format: string, timezone: string): Date | null {
    try {
      if (format === 'auto-detect') {
        return new Date(value);
      } else {
        // Parse according to specific format
        return new Date(value);
      }
    } catch (error: any) {
      return null;
    }
  }

  private convertToNumber(value: any, format: string): number | null {
    try {
      if (format === 'locale-aware') {
        // Handle different locale number formats
        const normalized = String(value).replace(/[,\s]/g, '');
        return Number(normalized);
      } else {
        return Number(value);
      }
    } catch (error: any) {
      return null;
    }
  }

  private convertToBoolean(value: any, mapping: string): boolean {
    if (mapping === 'fuzzy-match') {
      const stringValue = String(value).toLowerCase();
      const truthyValues = ['true', 'yes', 'y', '1', 'on', 'enabled', 'active'];
      const falsyValues = ['false', 'no', 'n', '0', 'off', 'disabled', 'inactive'];

      if (truthyValues.includes(stringValue)) return true;
      if (falsyValues.includes(stringValue)) return false;
    }

    return Boolean(value);
  }

  private validateBusinessConstraints(key: string, value: any, record: Record<string, any>): void {
    // Example business constraint validations
    if (key === 'email' && !this.isValidEmail(String(value))) {
      throw new Error(`Invalid email format: ${value}`);
    }

    if (key === 'age' && (Number(value) < 0 || Number(value) > 150)) {
      throw new Error(`Invalid age: ${value}`);
    }

    if (key === 'amount' && Number(value) < 0) {
      throw new Error(`Amount cannot be negative: ${value}`);
    }
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private extractCountry(context: any[]): string {
    const countryContext = context?.find(c => c.id.includes('country'));
    return countryContext?.text || 'Unknown';
  }

  private getTimezoneFromCoordinates(lat: number, lng: number): string {
    // Simplified timezone detection - in production, use a proper timezone API
    return 'UTC';
  }

  private getLookupTables(): Map<string, any[]> {
    // This would load lookup tables from D1 or R2
    return new Map();
  }

  async processBatch(
    records: Record<string, any>[],
    pipeline: Pipeline,
    batchId: string
  ): Promise<Record<string, any>[]> {
    const results: Record<string, any>[] = [];
    const context: TransformationContext = {
      record: {},
      metadata: { batchId },
      batchId,
      index: 0,
      lookup: this.lookupService,
      env: this.env
    };

    for (let i = 0; i < records.length; i++) {
      context.record = records[i];
      context.index = i;

      try {
        const transformed = await this.processRecord(records[i], pipeline, context);
        results.push(transformed);
      } catch (error: any) {
        // Handle individual record errors based on pipeline error handling
        if (pipeline.errorHandling.onError === 'SKIP') {
          continue;
        } else {
          throw error;
        }
      }
    }

    return results;
  }
}