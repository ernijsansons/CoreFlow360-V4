import { Schema, Table, Column, ConnectionConfig } from '../../../types/migration';
import { BaseConnector, Connector, QueryOptions, WriteOptions } from './index';

interface FileFormat {
  name: string;
  extensions: string[];
  parser: (content: string | ArrayBuffer, options?: any) => any[];
  serializer: (data: any[], options?: any) => string | ArrayBuffer;
  detectSchema: (data: any[]) => Column[];
}

interface ParseOptions {
  delimiter?: string;
  quote?: string;
  escape?: string;
  header?: boolean;
  encoding?: string;
  skipEmptyLines?: boolean;
  skipLinesWithError?: boolean;
}

interface SerializeOptions {
  delimiter?: string;
  quote?: string;
  header?: boolean;
  encoding?: string;
  pretty?: boolean;
}

export class FileConnector extends BaseConnector {
  private formats: Map<string, FileFormat> = new Map();
  private cache: Map<string, any[]> = new Map();

  constructor(config: ConnectionConfig, env: any) {
    super(config, env);
    this.initializeFormats();
  }

  getConnectorInfo(): Connector {
    return {
      id: 'file',
      type: 'FILE',
      name: 'File Connector',
      description: 'Connects to various file formats (CSV, JSON, Excel, XML, Parquet)',
      supportedOperations: [
        {
          name: 'read',
          type: 'READ',
          description: 'Read data from files',
          parameters: { path: 'string', format: 'string' }
        },
        {
          name: 'write',
          type: 'WRITE',
          description: 'Write data to files',
          parameters: { path: 'string', format: 'string', data: 'array' }
        },
        {
          name: 'schema',
          type: 'SCHEMA',
          description: 'Detect file schema',
          parameters: { path: 'string' }
        }
      ],
      configSchema: {
        path: { type: 'string', required: true },
        format: { type: 'string', enum: ['csv', 'json', 'excel', 'xml', 'parquet', 'auto'], required: false },
        encoding: { type: 'string', enum: ['utf-8', 'latin1', 'ascii'], required: false },
        parseOptions: { type: 'object', required: false },
        serializeOptions: { type: 'object', required: false }
      }
    };
  }

  async testConnection(): Promise<boolean> {
    try {
      const path = this.config.filePath || this.config.parameters.path;
      const exists = await this.fileExists(path);

      if (!exists) {
        // For write-only operations, test if we can create the file
        await this.writeFile(path, 'test');
        await this.deleteFile(path);
      }

      return true;
    } catch (error) {
      this.logError('testConnection', error as Error);
      return false;
    }
  }

  async getSchema(): Promise<Schema> {
    const path = this.config.filePath || this.config.parameters.path;
    const format = this.detectFormat(path);
    const data = await this.readFile(path, { limit: 100 }); // Sample first 100 rows

    const columns = this.detectSchemaFromData(data, format);

    return {
      name: this.getFileNameFromPath(path),
      tables: [{
        name: this.getFileNameFromPath(path),
        columns,
        primaryKey: [],
        foreignKeys: [],
        indexes: [],
        constraints: [],
        metadata: { format, path }
      }],
      version: '1.0',
      metadata: { format, path }
    };
  }

  async read(table: string, options: QueryOptions = {}): Promise<any[]> {
    const path = this.resolvePath(table);
    return await this.readFile(path, options);
  }

  async write(table: string, data: any[], options: WriteOptions = {}): Promise<{ success: number; errors: number }> {
    try {
      const path = this.resolvePath(table);
      await this.writeFile(path, data, options);
      return { success: data.length, errors: 0 };
    } catch (error) {
      this.logError('write', error as Error);
      return { success: 0, errors: data.length };
    }
  }

  async validateConfig(): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    if (!this.config.filePath && !this.config.parameters.path) {
      errors.push('File path is required');
    }

    const format = this.config.parameters.format;
    if (format && format !== 'auto' && !this.formats.has(format)) {
      errors.push(`Unsupported format: ${format}`);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  private initializeFormats(): void {
    // CSV Format
    this.formats.set('csv', {
      name: 'CSV',
      extensions: ['.csv', '.tsv'],
      parser: this.parseCSV.bind(this),
      serializer: this.serializeCSV.bind(this),
      detectSchema: this.detectCSVSchema.bind(this)
    });

    // JSON Format
    this.formats.set('json', {
      name: 'JSON',
      extensions: ['.json', '.jsonl'],
      parser: this.parseJSON.bind(this),
      serializer: this.serializeJSON.bind(this),
      detectSchema: this.detectJSONSchema.bind(this)
    });

    // Excel Format
    this.formats.set('excel', {
      name: 'Excel',
      extensions: ['.xlsx', '.xls'],
      parser: this.parseExcel.bind(this),
      serializer: this.serializeExcel.bind(this),
      detectSchema: this.detectExcelSchema.bind(this)
    });

    // XML Format
    this.formats.set('xml', {
      name: 'XML',
      extensions: ['.xml'],
      parser: this.parseXML.bind(this),
      serializer: this.serializeXML.bind(this),
      detectSchema: this.detectXMLSchema.bind(this)
    });

    // Parquet Format (for big data)
    this.formats.set('parquet', {
      name: 'Parquet',
      extensions: ['.parquet'],
      parser: this.parseParquet.bind(this),
      serializer: this.serializeParquet.bind(this),
      detectSchema: this.detectParquetSchema.bind(this)
    });
  }

  private async readFile(path: string, options: QueryOptions = {}): Promise<any[]> {
    const cacheKey = `${path}:${JSON.stringify(options)}`;

    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!;
    }

    const content = await this.getFileContent(path);
    const format = this.detectFormat(path);
    const formatHandler = this.formats.get(format);

    if (!formatHandler) {
      throw new Error(`Unsupported file format: ${format}`);
    }

    const parseOptions = {
      ...this.config.parameters.parseOptions,
      encoding: this.config.parameters.encoding || 'utf-8'
    };

    let data = formatHandler.parser(content, parseOptions);

    // Apply filters
    if (options.filters) {
      data = this.applyFilters(data, options.filters);
    }

    // Apply sorting
    if (options.orderBy) {
      data = this.applySorting(data, options.orderBy, options.orderDirection);
    }

    // Apply pagination
    if (options.offset || options.limit) {
      const start = options.offset || 0;
      const end = options.limit ? start + options.limit : undefined;
      data = data.slice(start, end);
    }

    // Cache the result
    this.cache.set(cacheKey, data);

    return data;
  }

  private async writeFile(path: string, data: any[] | string, options: WriteOptions = {}): Promise<void> {
    if (typeof data === 'string') {
      // Direct content write
      await this.putFileContent(path, data);
      return;
    }

    const format = this.detectFormat(path);
    const formatHandler = this.formats.get(format);

    if (!formatHandler) {
      throw new Error(`Unsupported file format: ${format}`);
    }

    const serializeOptions = {
      ...this.config.parameters.serializeOptions,
      encoding: this.config.parameters.encoding || 'utf-8'
    };

    const content = formatHandler.serializer(data, serializeOptions);
    await this.putFileContent(path, content);

    // Clear cache for this path
    for (const key of this.cache.keys()) {
      if (key.startsWith(path)) {
        this.cache.delete(key);
      }
    }
  }

  private async getFileContent(path: string): Promise<string | ArrayBuffer> {
    if (this.env.R2_BUCKET && path.startsWith('r2://')) {
      // R2 storage
      const r2Path = path.replace('r2://', '');
      const object = await this.env.R2_BUCKET.get(r2Path);

      if (!object) {
        throw new Error(`File not found: ${path}`);
      }

      return await object.text();
    } else if (path.startsWith('http://') || path.startsWith('https://')) {
      // HTTP(S) URL
      const response = await fetch(path, {
        headers: this.config.headers || {}
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch file: ${response.statusText}`);
      }

      return await response.text();
    } else {
      // Local file (not typically available in Cloudflare Workers)
      throw new Error('Local file access not supported in this environment');
    }
  }

  private async putFileContent(path: string, content: string | ArrayBuffer): Promise<void> {
    if (this.env.R2_BUCKET && path.startsWith('r2://')) {
      // R2 storage
      const r2Path = path.replace('r2://', '');
      await this.env.R2_BUCKET.put(r2Path, content);
    } else {
      throw new Error('File writing only supported for R2 storage');
    }
  }

  private async fileExists(path: string): Promise<boolean> {
    try {
      if (this.env.R2_BUCKET && path.startsWith('r2://')) {
        const r2Path = path.replace('r2://', '');
        const object = await this.env.R2_BUCKET.head(r2Path);
        return object !== null;
      } else if (path.startsWith('http://') || path.startsWith('https://')) {
        const response = await fetch(path, { method: 'HEAD' });
        return response.ok;
      }
      return false;
    } catch {
      return false;
    }
  }

  private async deleteFile(path: string): Promise<void> {
    if (this.env.R2_BUCKET && path.startsWith('r2://')) {
      const r2Path = path.replace('r2://', '');
      await this.env.R2_BUCKET.delete(r2Path);
    }
  }

  private detectFormat(path: string): string {
    const configFormat = this.config.parameters.format;

    if (configFormat && configFormat !== 'auto') {
      return configFormat;
    }

    // Auto-detect from file extension
    const extension = path.toLowerCase().substring(path.lastIndexOf('.'));

    for (const [format, info] of this.formats) {
      if (info.extensions.includes(extension)) {
        return format;
      }
    }

    return 'csv'; // Default fallback
  }

  private parseCSV(content: string, options: ParseOptions = {}): any[] {
    const delimiter = options.delimiter || ',';
    const quote = options.quote || '"';
    const hasHeader = options.header !== false;

    const lines = content.split('\n').filter(line => line.trim());
    if (lines.length === 0) return [];

    const data: any[] = [];
    const headers = hasHeader ? this.parseCSVLine(lines[0], delimiter, quote) : null;
    const startIndex = hasHeader ? 1 : 0;

    for (let i = startIndex; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      try {
        const values = this.parseCSVLine(line, delimiter, quote);

        if (headers) {
          const record: Record<string, any> = {};
          headers.forEach((header, index) => {
            record[header] = this.parseValue(values[index] || '');
          });
          data.push(record);
        } else {
          data.push(values.map(value => this.parseValue(value)));
        }
      } catch (error) {
        if (!options.skipLinesWithError) {
          throw new Error(`Error parsing CSV line ${i + 1}: ${error}`);
        }
      }
    }

    return data;
  }

  private parseCSVLine(line: string, delimiter: string, quote: string): string[] {
    const values: string[] = [];
    let current = '';
    let inQuotes = false;
    let i = 0;

    while (i < line.length) {
      const char = line[i];
      const nextChar = line[i + 1];

      if (char === quote) {
        if (inQuotes && nextChar === quote) {
          // Escaped quote
          current += quote;
          i += 2;
        } else {
          // Toggle quote state
          inQuotes = !inQuotes;
          i++;
        }
      } else if (char === delimiter && !inQuotes) {
        // End of field
        values.push(current);
        current = '';
        i++;
      } else {
        current += char;
        i++;
      }
    }

    values.push(current);
    return values;
  }

  private serializeCSV(data: any[], options: SerializeOptions = {}): string {
    const delimiter = options.delimiter || ',';
    const quote = options.quote || '"';
    const includeHeader = options.header !== false;

    if (data.length === 0) return '';

    const isObjectArray = typeof data[0] === 'object' && !Array.isArray(data[0]);
    const headers = isObjectArray ? Object.keys(data[0]) : null;

    const lines: string[] = [];

    // Add header if needed
    if (includeHeader && headers) {
      lines.push(headers.map(h => this.escapeCSVValue(h, delimiter, quote)).join(delimiter));
    }

    // Add data rows
    for (const row of data) {
      const values = isObjectArray
        ? headers!.map(h => row[h])
        : Array.isArray(row) ? row : [row];

      const escapedValues = values.map(v =>
        this.escapeCSVValue(String(v ?? ''), delimiter, quote)
      );

      lines.push(escapedValues.join(delimiter));
    }

    return lines.join('\n');
  }

  private escapeCSVValue(value: string, delimiter: string, quote: string): string {
    if (value.includes(delimiter) || value.includes(quote) || value.includes('\n')) {
      return quote + value.replace(new RegExp(quote, 'g'), quote + quote) + quote;
    }
    return value;
  }

  private parseJSON(content: string, options: ParseOptions = {}): any[] {
    try {
      const parsed = JSON.parse(content);

      if (Array.isArray(parsed)) {
        return parsed;
      } else if (typeof parsed === 'object') {
        // Single object, wrap in array
        return [parsed];
      } else {
        throw new Error('JSON content must be an array or object');
      }
    } catch (error) {
      // Try parsing as JSONL (JSON Lines)
      const lines = content.split('\n').filter(line => line.trim());
      const data: any[] = [];

      for (const line of lines) {
        try {
          data.push(JSON.parse(line));
        } catch (lineError) {
          if (!options.skipLinesWithError) {
            throw new Error(`Invalid JSON line: ${line}`);
          }
        }
      }

      return data;
    }
  }

  private serializeJSON(data: any[], options: SerializeOptions = {}): string {
    if (options.pretty) {
      return JSON.stringify(data, null, 2);
    }
    return JSON.stringify(data);
  }

  private parseExcel(content: string | ArrayBuffer, options: ParseOptions = {}): any[] {
    // Simplified Excel parsing - in production, use a library like xlsx
    throw new Error('Excel parsing not implemented in this simplified version');
  }

  private serializeExcel(data: any[], options: SerializeOptions = {}): ArrayBuffer {
    // Simplified Excel serialization
    throw new Error('Excel serialization not implemented in this simplified version');
  }

  private parseXML(content: string, options: ParseOptions = {}): any[] {
    // Simplified XML parsing - in production, use a proper XML parser
    throw new Error('XML parsing not implemented in this simplified version');
  }

  private serializeXML(data: any[], options: SerializeOptions = {}): string {
    // Simplified XML serialization
    throw new Error('XML serialization not implemented in this simplified version');
  }

  private parseParquet(content: ArrayBuffer, options: ParseOptions = {}): any[] {
    // Simplified Parquet parsing - in production, use a library like parquetjs
    throw new Error('Parquet parsing not implemented in this simplified version');
  }

  private serializeParquet(data: any[], options: SerializeOptions = {}): ArrayBuffer {
    // Simplified Parquet serialization
    throw new Error('Parquet serialization not implemented in this simplified version');
  }

  private parseValue(value: string): any {
    // Trim whitespace
    value = value.trim();

    // Empty string
    if (value === '') return '';

    // Boolean values
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;

    // Null values
    if (value.toLowerCase() === 'null' || value.toLowerCase() === 'nil') return null;

    // Numbers
    if (/^-?\d+$/.test(value)) {
      return parseInt(value, 10);
    }
    if (/^-?\d*\.\d+$/.test(value)) {
      return parseFloat(value);
    }

    // Dates (basic detection)
    if (/^\d{4}-\d{2}-\d{2}/.test(value)) {
      const date = new Date(value);
      if (!isNaN(date.getTime())) {
        return date.toISOString();
      }
    }

    // Return as string
    return value;
  }

  private detectSchemaFromData(data: any[], format: string): Column[] {
    const formatHandler = this.formats.get(format);

    if (formatHandler) {
      return formatHandler.detectSchema(data);
    }

    return this.detectGenericSchema(data);
  }

  private detectCSVSchema(data: any[]): Column[] {
    return this.detectGenericSchema(data);
  }

  private detectJSONSchema(data: any[]): Column[] {
    return this.detectGenericSchema(data);
  }

  private detectExcelSchema(data: any[]): Column[] {
    return this.detectGenericSchema(data);
  }

  private detectXMLSchema(data: any[]): Column[] {
    return this.detectGenericSchema(data);
  }

  private detectParquetSchema(data: any[]): Column[] {
    return this.detectGenericSchema(data);
  }

  private detectGenericSchema(data: any[]): Column[] {
    if (data.length === 0) return [];

    const columns: Column[] = [];
    const sample = data[0];

    if (typeof sample === 'object' && !Array.isArray(sample)) {
      // Object array
      for (const [key, value] of Object.entries(sample)) {
        columns.push({
          name: key,
          type: this.inferDataType(value, data.map(row => row[key])),
          nullable: data.some(row => row[key] === null || row[key] === undefined),
          metadata: { inferred: true }
        });
      }
    } else if (Array.isArray(sample)) {
      // Array of arrays
      sample.forEach((_, index) => {
        const columnValues = data.map(row => Array.isArray(row) ? row[index] : undefined);
        columns.push({
          name: `column_${index}`,
          type: this.inferDataType(sample[index], columnValues),
          nullable: columnValues.some(val => val === null || val === undefined),
          metadata: { inferred: true }
        });
      });
    } else {
      // Array of primitives
      columns.push({
        name: 'value',
        type: this.inferDataType(sample, data),
        nullable: data.some(val => val === null || val === undefined),
        metadata: { inferred: true }
      });
    }

    return columns;
  }

  private inferDataType(sample: any, values: any[]): string {
    const types = new Set<string>();

    values.forEach(value => {
      if (value === null || value === undefined) {
        types.add('null');
      } else if (typeof value === 'boolean') {
        types.add('boolean');
      } else if (typeof value === 'number') {
        types.add(Number.isInteger(value) ? 'integer' : 'decimal');
      } else if (typeof value === 'string') {
        if (this.isDateString(value)) {
          types.add('datetime');
        } else {
          types.add('varchar');
        }
      } else if (Array.isArray(value)) {
        types.add('array');
      } else if (typeof value === 'object') {
        types.add('json');
      } else {
        types.add('varchar');
      }
    });

    // Remove null type for determination
    types.delete('null');

    if (types.size === 0) return 'varchar';
    if (types.size === 1) return Array.from(types)[0];

    // Multiple types detected - return most general
    if (types.has('varchar')) return 'varchar';
    if (types.has('decimal')) return 'decimal';
    if (types.has('integer')) return 'integer';

    return 'varchar';
  }

  private isDateString(value: string): boolean {
    const date = new Date(value);
    return !isNaN(date.getTime()) && value.match(/\d{4}-\d{2}-\d{2}/);
  }

  private applyFilters(data: any[], filters: Record<string, any>): any[] {
    return data.filter(row => {
      return Object.entries(filters).every(([key, value]) => {
        const rowValue = row[key];

        if (Array.isArray(value)) {
          return value.includes(rowValue);
        } else if (typeof value === 'object' && value !== null) {
          // Complex filter object
          const { operator, value: filterValue } = value;
          switch (operator) {
            case 'gt': return rowValue > filterValue;
            case 'gte': return rowValue >= filterValue;
            case 'lt': return rowValue < filterValue;
            case 'lte': return rowValue <= filterValue;
            case 'ne': return rowValue !== filterValue;
            case 'like': return String(rowValue).includes(String(filterValue));
            default: return rowValue === filterValue;
          }
        } else {
          return rowValue === value;
        }
      });
    });
  }

  private applySorting(data: any[], orderBy: string, direction: string = 'ASC'): any[] {
    return data.sort((a, b) => {
      const aValue = a[orderBy];
      const bValue = b[orderBy];

      let comparison = 0;

      if (aValue < bValue) comparison = -1;
      else if (aValue > bValue) comparison = 1;

      return direction === 'DESC' ? -comparison : comparison;
    });
  }

  private resolvePath(table: string): string {
    const basePath = this.config.filePath || this.config.parameters.path;

    if (basePath.includes('{table}')) {
      return basePath.replace('{table}', table);
    }

    return basePath;
  }

  private getFileNameFromPath(path: string): string {
    const parts = path.split('/');
    const fileName = parts[parts.length - 1];
    const dotIndex = fileName.lastIndexOf('.');

    return dotIndex > 0 ? fileName.substring(0, dotIndex) : fileName;
  }

  clearCache(): void {
    this.cache.clear();
  }

  getCacheSize(): number {
    return this.cache.size;
  }
}