import { Schema, MappingRules, TableMapping, ColumnMapping, Transformation, Correction } from '../../types/migration';

interface SemanticAnalysis {
  fieldSemantics: Map<string, FieldSemantic>;
  relationships: Relationship[];
  patterns: Pattern[];
  confidence: number;
}

interface FieldSemantic {
  field: string;
  category: string;
  dataType: string;
  semanticType: string;
  businessConcept: string;
  examples: any[];
  patterns: string[];
  constraints: string[];
}

interface Relationship {
  sourceField: string;
  targetField: string;
  relationshipType: 'IDENTICAL' | 'SIMILAR' | 'DERIVED' | 'COMPOSITE';
  confidence: number;
  evidence: string[];
}

interface Pattern {
  type: 'NAMING' | 'DATA_TYPE' | 'VALUE_RANGE' | 'FORMAT';
  pattern: string;
  frequency: number;
  confidence: number;
}

interface MappingStrategy {
  name: string;
  weight: number;
  threshold: number;
  algorithm: (source: FieldSemantic, target: FieldSemantic) => number;
}

export class AISchemaMapper {
  private env: any;
  private previousMappings: Map<string, MappingRules> = new Map();
  private mlModel: any;
  private semanticCache: Map<string, SemanticAnalysis> = new Map();

  constructor(env: any) {
    this.env = env;
    this.loadPreviousMappings();
  }

  async generateMapping(source: Schema, target: Schema): Promise<MappingRules> {

    // Step 1: Analyze semantics of both schemas
    const sourceAnalysis = await this.analyzeSemantics(source);
    const targetAnalysis = await this.analyzeSemantics(target);

    // Step 2: Generate initial mapping using multiple strategies
    const mapping = await this.createMapping(sourceAnalysis, targetAnalysis, {
      strategy: 'semantic-similarity',
      threshold: 0.8,
      handleAmbiguity: 'prompt-user',
      preserveRelationships: true
    });

    // Step 3: Validate mapping with test data
    const validation = await this.validateMapping(mapping, source, target);

    // Step 4: Optimize based on validation results
    const optimizedMapping = await this.optimizeMapping(mapping, validation);

    return optimizedMapping;
  }

  private async analyzeSemantics(schema: Schema): Promise<SemanticAnalysis> {
    const cacheKey = `${schema.name}:${schema.version}`;

    if (this.semanticCache.has(cacheKey)) {
      return this.semanticCache.get(cacheKey)!;
    }

    const analysis: SemanticAnalysis = {
      fieldSemantics: new Map(),
      relationships: [],
      patterns: [],
      confidence: 0
    };

    // Analyze each table and column
    for (const table of schema.tables) {
      for (const column of table.columns) {
        const semantic = await this.analyzeFieldSemantic(table.name, column, schema);
        analysis.fieldSemantics.set(`${table.name}.${column.name}`, semantic);
      }
    }

    // Detect relationships between fields
    analysis.relationships = await this.detectRelationships(analysis.fieldSemantics);

    // Identify patterns
    analysis.patterns = await this.identifyPatterns(analysis.fieldSemantics);

    // Calculate overall confidence
    analysis.confidence = this.calculateAnalysisConfidence(analysis);

    this.semanticCache.set(cacheKey, analysis);
    return analysis;
  }

  private async analyzeFieldSemantic(tableName: string, column: any, schema: Schema): Promise<FieldSemantic> {
    // Get sample data to understand the field better
    const sampleData = await this.getSampleData(tableName, column.name);

    // Use AI to analyze semantic meaning
    const aiAnalysis = await this.performAIAnalysis(column, sampleData);

    // Combine with rule-based analysis
    const ruleBasedAnalysis = this.performRuleBasedAnalysis(column, sampleData);

    return {
      field: `${tableName}.${column.name}`,
      category: this.categorizeField(column),
      dataType: column.type,
      semanticType: aiAnalysis.semanticType || this.inferSemanticType(column, sampleData),
      businessConcept: aiAnalysis.businessConcept || this.inferBusinessConcept(column),
      examples: sampleData.slice(0, 10),
      patterns: this.extractPatterns(sampleData),
      constraints: this.extractConstraints(column)
    };
  }

  private async performAIAnalysis(column: any, sampleData: any[]): Promise<any> {
    if (!this.env.AI_ENDPOINT) {
      return { semanticType: null, businessConcept: null };
    }

    try {
      const prompt = `
        Analyze this database column and determine its semantic meaning:

        Column Name: ${column.name}
        Data Type: ${column.type}
        Nullable: ${column.nullable}
        Sample Values: ${JSON.stringify(sampleData.slice(0, 20))}

        Please determine:
        1. Semantic Type (e.g., identifier, name, date, amount, email, phone, address)
        2. Business Concept (e.g., customer_id, order_date, product_price, user_email)
        3. Confidence Score (0-1)

        Respond in JSON format.
      `;

      const response = await fetch(this.env.AI_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.env.AI_API_KEY}`
        },
        body: JSON.stringify({
          model: 'claude-3-sonnet',
          messages: [{ role: 'user', content: prompt }],
          max_tokens: 500
        })
      });

      const result = await response.json();
      return JSON.parse(result.content || '{}');
    } catch (error: any) {
      return { semanticType: null, businessConcept: null };
    }
  }

  private performRuleBasedAnalysis(column: any, sampleData: any[]): any {
    const analysis = {
      semanticType: this.inferSemanticType(column, sampleData),
      businessConcept: this.inferBusinessConcept(column),
      confidence: 0.7
    };

    return analysis;
  }

  private inferSemanticType(column: any, sampleData: any[]): string {
    const name = column.name.toLowerCase();
    const type = column.type.toLowerCase();

    // ID patterns
    if (name.includes('id') || name.endsWith('_id') || name === 'id') {
      return 'identifier';
    }

    // Date patterns
    if (type.includes('date') || type.includes('time') || type.includes('timestamp')) {
      return 'datetime';
    }

    // Email patterns
    if (name.includes('email') || name.includes('mail')) {
      return 'email';
    }

    // Phone patterns
    if (name.includes('phone') || name.includes('tel') || name.includes('mobile')) {
      return 'phone';
    }

    // Name patterns
    if (name.includes('name') || name.includes('title')) {
      return 'name';
    }

    // Address patterns
    if (name.includes('address') || name.includes('street') || name.includes('city') || name.includes('zip')) {
      return 'address';
    }

    // Amount/Price patterns
    if (name.includes('price') || name.includes('amount') || name.includes('cost') || name.includes('value')) {
      return 'monetary';
    }

    // Analyze sample data patterns
    if (sampleData.length > 0) {
      const firstValue = sampleData[0];

      if (typeof firstValue === 'string') {
        if (this.isEmailPattern(firstValue)) return 'email';
        if (this.isPhonePattern(firstValue)) return 'phone';
        if (this.isUrlPattern(firstValue)) return 'url';
        if (this.isDatePattern(firstValue)) return 'datetime';
      }
    }

    // Default to text for strings, number for numeric types
    if (type.includes('varchar') || type.includes('text') || type.includes('char')) {
      return 'text';
    }

    if (type.includes('int') || type.includes('decimal') || type.includes('float') || type.includes('numeric')) {
      return 'number';
    }

    return 'unknown';
  }

  private inferBusinessConcept(column: any): string {
    const name = column.name.toLowerCase();

    // Common business concepts
    const businessConcepts = {
      'customer': ['customer_id', 'customer_name', 'customer_email'],
      'user': ['user_id', 'username', 'user_email'],
      'order': ['order_id', 'order_date', 'order_total'],
      'product': ['product_id', 'product_name', 'product_price'],
      'invoice': ['invoice_id', 'invoice_date', 'invoice_amount'],
      'payment': ['payment_id', 'payment_date', 'payment_amount'],
      'address': ['street_address', 'city', 'state', 'zip_code', 'country']
    };

    for (const [concept, patterns] of Object.entries(businessConcepts)) {
      if (patterns.some(pattern => name.includes(pattern.replace(/_/g, '')))) {
        return concept;
      }
    }

    return 'general';
  }

  private async detectRelationships(fieldSemantics: Map<string, FieldSemantic>): Promise<Relationship[]> {
    const relationships: Relationship[] = [];
    const fields = Array.from(fieldSemantics.values());

    // Compare each field with every other field
    for (let i = 0; i < fields.length; i++) {
      for (let j = i + 1; j < fields.length; j++) {
        const sourceField = fields[i];
        const targetField = fields[j];

        const relationship = this.analyzeFieldRelationship(sourceField, targetField);
        if (relationship.confidence > 0.6) {
          relationships.push(relationship);
        }
      }
    }

    return relationships;
  }

  private analyzeFieldRelationship(source: FieldSemantic, target: FieldSemantic): Relationship {
    let confidence = 0;
    let relationshipType: 'IDENTICAL' | 'SIMILAR' | 'DERIVED' | 'COMPOSITE' = 'SIMILAR';
    const evidence: string[] = [];

    // Exact name match
    if (source.field.split('.')[1] === target.field.split('.')[1]) {
      confidence += 0.8;
      relationshipType = 'IDENTICAL';
      evidence.push('Exact column name match');
    }

    // Semantic type match
    if (source.semanticType === target.semanticType) {
      confidence += 0.6;
      evidence.push('Same semantic type');
    }

    // Business concept match
    if (source.businessConcept === target.businessConcept) {
      confidence += 0.5;
      evidence.push('Same business concept');
    }

    // Similar naming patterns
    const sourceName = source.field.split('.')[1].toLowerCase();
    const targetName = target.field.split('.')[1].toLowerCase();
    const similarity = this.calculateStringSimilarity(sourceName, targetName);

    if (similarity > 0.7) {
      confidence += similarity * 0.4;
      evidence.push(`High name similarity: ${similarity.toFixed(2)}`);
    }

    // Data type compatibility
    if (this.areDataTypesCompatible(source.dataType, target.dataType)) {
      confidence += 0.3;
      evidence.push('Compatible data types');
    }

    return {
      sourceField: source.field,
      targetField: target.field,
      relationshipType,
      confidence: Math.min(confidence, 1.0),
      evidence
    };
  }

  private async createMapping(
    sourceAnalysis: SemanticAnalysis,
    targetAnalysis: SemanticAnalysis,
    options: any
  ): Promise<MappingRules> {
    const mappingRules: MappingRules = {
      id: crypto.randomUUID(),
      sourceSchema: 'source',
      targetSchema: 'target',
      tableMappings: [],
      globalTransformations: [],
      confidence: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: {}
    };

    // Group fields by table
    const sourceTables = this.groupFieldsByTable(sourceAnalysis.fieldSemantics);
    const targetTables = this.groupFieldsByTable(targetAnalysis.fieldSemantics);

    // Create table mappings
    for (const [sourceTable, sourceFields] of sourceTables) {
      const bestTargetTable = this.findBestTableMatch(sourceTable, sourceFields, targetTables);

      if (bestTargetTable) {
        const tableMapping = await this.createTableMapping(
          sourceTable,
          sourceFields,
          bestTargetTable.name,
          bestTargetTable.fields,
          options
        );
        mappingRules.tableMappings.push(tableMapping);
      }
    }

    // Calculate overall confidence
    mappingRules.confidence = this.calculateMappingConfidence(mappingRules);

    return mappingRules;
  }

  private async createTableMapping(
    sourceTable: string,
    sourceFields: FieldSemantic[],
    targetTable: string,
    targetFields: FieldSemantic[],
    options: any
  ): Promise<TableMapping> {
    const columnMappings: ColumnMapping[] = [];

    // Apply multiple mapping strategies
    const strategies: MappingStrategy[] = [
      {
        name: 'exact_match',
        weight: 1.0,
        threshold: 0.95,
        algorithm: this.exactMatchStrategy
      },
      {
        name: 'semantic_similarity',
        weight: 0.8,
        threshold: 0.7,
        algorithm: this.semanticSimilarityStrategy
      },
      {
        name: 'fuzzy_name_match',
        weight: 0.6,
        threshold: 0.6,
        algorithm: this.fuzzyNameMatchStrategy
      },
      {
        name: 'data_type_compatibility',
        weight: 0.4,
        threshold: 0.5,
        algorithm: this.dataTypeCompatibilityStrategy
      }
    ];

    // For each source field, find the best target field
    for (const sourceField of sourceFields) {
      let bestMatch: ColumnMapping | null = null;
      let bestScore = 0;

      for (const targetField of targetFields) {
        let totalScore = 0;
        let weightSum = 0;

        // Apply each strategy
        for (const strategy of strategies) {
          const score = strategy.algorithm(sourceField, targetField);
          if (score >= strategy.threshold) {
            totalScore += score * strategy.weight;
            weightSum += strategy.weight;
          }
        }

        const finalScore = weightSum > 0 ? totalScore / weightSum : 0;

        if (finalScore > bestScore && finalScore >= options.threshold) {
          bestScore = finalScore;
          bestMatch = {
            sourceColumn: sourceField.field.split('.')[1],
            targetColumn: targetField.field.split('.')[1],
            confidence: finalScore,
            required: !sourceField.field.includes('nullable'),
            metadata: {
              strategy: 'ai_generated',
              scores: strategies.map((s: any) => ({
                name: s.name,
                score: s.algorithm(sourceField, targetField)
              }))
            }
          };
        }
      }

      if (bestMatch) {
        // Add transformation if data types don't match exactly
        if
  (!this.areDataTypesIdentical(sourceField.dataType, targetFields.find(f => f.field.split('.')[1] === bestMatch!.targetColumn)?.dataType || '')) {
        
   bestMatch.transformation = this.generateTransformation(sourceField, targetFields.find(f => f.field.split('.')[1] === bestMatch!.targetColumn)!);
        }

        columnMappings.push(bestMatch);
      }
    }

    return {
      sourceTable,
      targetTable,
      columnMappings,
      filters: [],
      transformations: [],
      confidence: columnMappings.reduce((sum, cm) => sum + cm.confidence, 0) / Math.max(columnMappings.length, 1)
    };
  }

  private exactMatchStrategy = (source: FieldSemantic, target: FieldSemantic): number => {
    const sourceName = source.field.split('.')[1].toLowerCase();
    const targetName = target.field.split('.')[1].toLowerCase();
    return sourceName === targetName ? 1.0 : 0.0;
  };

  private semanticSimilarityStrategy = (source: FieldSemantic, target: FieldSemantic): number => {
    let score = 0;

    // Semantic type match
    if (source.semanticType === target.semanticType) {
      score += 0.4;
    }

    // Business concept match
    if (source.businessConcept === target.businessConcept) {
      score += 0.4;
    }

    // Category match
    if (source.category === target.category) {
      score += 0.2;
    }

    return score;
  };

  private fuzzyNameMatchStrategy = (source: FieldSemantic, target: FieldSemantic): number => {
    const sourceName = source.field.split('.')[1].toLowerCase();
    const targetName = target.field.split('.')[1].toLowerCase();
    return this.calculateStringSimilarity(sourceName, targetName);
  };

  private dataTypeCompatibilityStrategy = (source: FieldSemantic, target: FieldSemantic): number => {
    if (this.areDataTypesIdentical(source.dataType, target.dataType)) {
      return 1.0;
    }
    if (this.areDataTypesCompatible(source.dataType, target.dataType)) {
      return 0.7;
    }
    return 0.0;
  };

  private generateTransformation(source: FieldSemantic, target: FieldSemantic): Transformation {
    const sourceType = source.dataType.toLowerCase();
    const targetType = target.dataType.toLowerCase();

    // Date format transformations
    if (source.semanticType === 'datetime' && target.semanticType === 'datetime') {
      return {
        id: crypto.randomUUID(),
        type: 'EXPRESSION',
        expression: 'FORMAT_DATE(${value}, "YYYY-MM-DD HH:mm:ss")',
        parameters: {},
        description: 'Convert date format'
      };
    }

    // String to number conversion
    if (sourceType.includes('varchar') && (targetType.includes('int') || targetType.includes('decimal'))) {
      return {
        id: crypto.randomUUID(),
        type: 'EXPRESSION',
        expression: 'CAST(${value} AS NUMERIC)',
        parameters: {},
        description: 'Convert string to number'
      };
    }

    // Number to string conversion
    if ((sourceType.includes('int') || sourceType.includes('decimal')) && targetType.includes('varchar')) {
      return {
        id: crypto.randomUUID(),
        type: 'EXPRESSION',
        expression: 'CAST(${value} AS VARCHAR)',
        parameters: {},
        description: 'Convert number to string'
      };
    }

    // Default direct mapping
    return {
      id: crypto.randomUUID(),
      type: 'DIRECT',
      parameters: {},
      description: 'Direct field mapping'
    };
  }

  async validateMapping(mapping: MappingRules, source: Schema, target: Schema): Promise<any> {
    const validation = {
      sampleSize: 1000,
      checkConstraints: true,
      checkBusinessRules: true,
      results: {
        accuracy: 0,
        completeness: 0,
        consistency: 0,
        issues: [] as any[]
      }
    };

    // Get sample data for validation
    const sampleData = await this.getSampleMappingData(mapping, validation.sampleSize);

    // Test each table mapping
    for (const tableMapping of mapping.tableMappings) {
      const tableSample = sampleData.filter((d: any) => d.table === tableMapping.sourceTable);

      // Validate column mappings
      for (const columnMapping of tableMapping.columnMappings) {
        const columnValidation = await this.validateColumnMapping(columnMapping, tableSample);
        validation.results.issues.push(...columnValidation.issues);
      }
    }

    // Calculate overall scores
    validation.results.accuracy = this.calculateAccuracy(validation.results.issues);
    validation.results.completeness = this.calculateCompleteness(mapping, source, target);
    validation.results.consistency = this.calculateConsistency(validation.results.issues);

    return validation;
  }

  async optimizeMapping(mapping: MappingRules, validation: any): Promise<MappingRules> {
    const optimized = { ...mapping };

    // Remove low-confidence mappings
    for (const tableMapping of optimized.tableMappings) {
      tableMapping.columnMappings = tableMapping.columnMappings.filter((cm: any) => cm.confidence >= 0.5);
    }

    // Add suggested transformations based on validation issues
    for (const issue of validation.results.issues) {
      if (issue.type === 'data_type_mismatch') {
        const mapping = this.findColumnMapping(optimized, issue.sourceColumn, issue.targetColumn);
        if (mapping && !mapping.transformation) {
          mapping.transformation = this.suggestTransformation(issue);
        }
      }
    }

    // Update confidence scores
    optimized.confidence = this.calculateMappingConfidence(optimized);

    return optimized;
  }

  async learnFromCorrections(corrections: Correction[]): Promise<void> {
    // Store corrections for future learning
    for (const correction of corrections) {
      await this.storeCorrectionFeedback(correction);
    }

    // Update ML model if enough corrections are available
    if (corrections.length >= 10) {
      await this.updateMLModel(corrections);
    }
  }

  private async storeCorrectionFeedback(correction: Correction): Promise<void> {
    // Store in D1 database for future reference
    // This would be implemented with actual database operations
  }

  private async updateMLModel(corrections: Correction[]): Promise<void> {
    if (!this.env.AI_ENDPOINT) return;

    try {
      // Fine-tune the model with corrections
      const trainingData = corrections.map((c: any) => ({
        input: {
          sourceField: c.sourceField,
          targetField: c.targetField,
          confidence: c.confidence
        },
        output: {
          correctMapping: c.correctMapping,
          transformation: c.transformation
        }
      }));

      // This would integrate with your ML training pipeline
    } catch (error: any) {
    }
  }

  // Utility methods
  private async loadPreviousMappings(): Promise<void> {
    // Load from D1 database
    // This would query actual previous mappings
  }

  private async getSampleData(tableName: string, columnName: string): Promise<any[]> {
    // This would query actual data from the source system
    return [];
  }

  private categorizeField(column: any): string {
    if (column.name.toLowerCase().includes('id')) return 'identifier';
    if (column.type.toLowerCase().includes('date')) return 'temporal';
    if (column.type.toLowerCase().includes('varchar')) return 'textual';
    if (column.type.toLowerCase().includes('int') || column.type.toLowerCase().includes('decimal')) return 'numeric';
    return 'other';
  }

  private extractPatterns(sampleData: any[]): string[] {
    const patterns: string[] = [];

    if (sampleData.length === 0) return patterns;

    // Check for common patterns
    const firstValue = sampleData[0];

    if (typeof firstValue === 'string') {
      if (this.isEmailPattern(firstValue)) patterns.push('email');
      if (this.isPhonePattern(firstValue)) patterns.push('phone');
      if (this.isDatePattern(firstValue)) patterns.push('date');
      if (this.isUrlPattern(firstValue)) patterns.push('url');
    }

    return patterns;
  }

  private extractConstraints(column: any): string[] {
    const constraints: string[] = [];

    if (!column.nullable) constraints.push('NOT_NULL');
    if (column.length) constraints.push(`MAX_LENGTH_${column.length}`);
    if (column.defaultValue) constraints.push(`DEFAULT_${column.defaultValue}`);

    return constraints;
  }

  private identifyPatterns(fieldSemantics: Map<string, FieldSemantic>): Pattern[] {
    const patterns: Pattern[] = [];

    // Analyze naming patterns
    const fieldNames = Array.from(fieldSemantics.keys()).map((k: any) => k.split('.')[1]);
    const namingPatterns = this.analyzePatternsInNames(fieldNames);
    patterns.push(...namingPatterns);

    return patterns;
  }

  private analyzePatternsInNames(names: string[]): Pattern[] {
    const patterns: Pattern[] = [];

    // Check for common prefixes/suffixes
    const prefixes = new Map<string, number>();
    const suffixes = new Map<string, number>();

    names.forEach((name: any) => {
      const parts = name.split('_');
      if (parts.length > 1) {
        const prefix = parts[0];
        const suffix = parts[parts.length - 1];
        prefixes.set(prefix, (prefixes.get(prefix) || 0) + 1);
        suffixes.set(suffix, (suffixes.get(suffix) || 0) + 1);
      }
    });

    // Convert to patterns
    prefixes.forEach((count, prefix) => {
      if (count > 1) {
        patterns.push({
          type: 'NAMING',
          pattern: `prefix_${prefix}`,
          frequency: count,
          confidence: count / names.length
        });
      }
    });

    return patterns;
  }

  private calculateAnalysisConfidence(analysis: SemanticAnalysis): number {
    const fieldConfidences = Array.from(analysis.fieldSemantics.values()).map((f: any) => 0.8); // Default confidence
    const avgFieldConfidence = fieldConfidences.reduce((sum, c) => sum + c, 0) / fieldConfidences.length;

    const relationshipConfidence = analysis.relationships.length > 0
      ? analysis.relationships.reduce((sum, r) => sum + r.confidence, 0) / analysis.relationships.length
      : 0.5;

    return (avgFieldConfidence * 0.7) + (relationshipConfidence * 0.3);
  }

  private groupFieldsByTable(fieldSemantics: Map<string, FieldSemantic>): Map<string, FieldSemantic[]> {
    const tables = new Map<string, FieldSemantic[]>();

    fieldSemantics.forEach((semantic, fieldName) => {
      const tableName = fieldName.split('.')[0];
      if (!tables.has(tableName)) {
        tables.set(tableName, []);
      }
      tables.get(tableName)!.push(semantic);
    });

    return tables;
  }

  private findBestTableMatch(
    sourceTable: string,
    sourceFields: FieldSemantic[],
    targetTables: Map<string, FieldSemantic[]>
  ): { name: string; fields: FieldSemantic[] } | null {
    let bestMatch: { name: string; fields: FieldSemantic[] } | null = null;
    let bestScore = 0;

    targetTables.forEach((targetFields, targetTable) => {
      const score = this.calculateTableSimilarity(sourceFields, targetFields);
      if (score > bestScore) {
        bestScore = score;
        bestMatch = { name: targetTable, fields: targetFields };
      }
    });

    return bestScore > 0.3 ? bestMatch : null;
  }

  private calculateTableSimilarity(sourceFields: FieldSemantic[], targetFields: FieldSemantic[]): number {
    let totalScore = 0;
    let comparisons = 0;

    sourceFields.forEach((sourceField: any) => {
      targetFields.forEach((targetField: any) => {
        const similarity = this.semanticSimilarityStrategy(sourceField, targetField);
        totalScore += similarity;
        comparisons++;
      });
    });

    return comparisons > 0 ? totalScore / comparisons : 0;
  }

  private calculateMappingConfidence(mapping: MappingRules): number {
    const tableConfidences = mapping.tableMappings.map((tm: any) => tm.confidence);
    return tableConfidences.length > 0
      ? tableConfidences.reduce((sum, c) => sum + c, 0) / tableConfidences.length
      : 0;
  }

  private calculateStringSimilarity(str1: string, str2: string): number {
    // Levenshtein distance-based similarity
    const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));

    for (let i = 0; i <= str1.length; i += 1) {
      matrix[0][i] = i;
    }

    for (let j = 0; j <= str2.length; j += 1) {
      matrix[j][0] = j;
    }

    for (let j = 1; j <= str2.length; j += 1) {
      for (let i = 1; i <= str1.length; i += 1) {
        const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[j][i] = Math.min(
          matrix[j][i - 1] + 1,
          matrix[j - 1][i] + 1,
          matrix[j - 1][i - 1] + indicator
        );
      }
    }

    const maxLength = Math.max(str1.length, str2.length);
    return maxLength === 0 ? 1 : (maxLength - matrix[str2.length][str1.length]) / maxLength;
  }

  private areDataTypesCompatible(type1: string, type2: string): boolean {
    const normalizedType1 = this.normalizeDataType(type1);
    const normalizedType2 = this.normalizeDataType(type2);

    const compatibilityMatrix = {
      'string': ['string', 'text'],
      'number': ['number', 'integer', 'decimal', 'float'],
      'date': ['date', 'datetime', 'timestamp'],
      'boolean': ['boolean', 'bit']
    };

    for (const [baseType, compatibleTypes] of Object.entries(compatibilityMatrix)) {
      if (compatibleTypes.includes(normalizedType1) && compatibleTypes.includes(normalizedType2)) {
        return true;
      }
    }

    return false;
  }

  private areDataTypesIdentical(type1: string, type2: string): boolean {
    return this.normalizeDataType(type1) === this.normalizeDataType(type2);
  }

  private normalizeDataType(type: string): string {
    const lowerType = type.toLowerCase();

    if (lowerType.includes('varchar') || lowerType.includes('char') || lowerType.includes('text')) {
      return 'string';
    }
    if (lowerType.includes('int') || lowerType.includes('integer')) {
      return 'integer';
    }
    if (lowerType.includes('decimal')
  || lowerType.includes('numeric') || lowerType.includes('float') || lowerType.includes('double')) {
      return 'decimal';
    }
    if (lowerType.includes('date') || lowerType.includes('time')) {
      return 'date';
    }
    if (lowerType.includes('bool') || lowerType.includes('bit')) {
      return 'boolean';
    }

    return lowerType;
  }

  private isEmailPattern(value: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(value);
  }

  private isPhonePattern(value: string): boolean {
    const phoneRegex = /^[\+]?[\d\s\-\(\)]{10,}$/;
    return phoneRegex.test(value);
  }

  private isUrlPattern(value: string): boolean {
    const urlRegex = /^https?:\/\/[^\s]+$/;
    return urlRegex.test(value);
  }

  private isDatePattern(value: string): boolean {
    return !isNaN(Date.parse(value));
  }

  private async getSampleMappingData(mapping: MappingRules, sampleSize: number): Promise<any[]> {
    // This would query actual sample data for validation
    return [];
  }

  private async validateColumnMapping(columnMapping: ColumnMapping, sampleData: any[]): Promise<any> {
    return {
      issues: []
    };
  }

  private calculateAccuracy(issues: any[]): number {
    // Calculate accuracy based on validation issues
    return Math.max(0, 1 - (issues.length * 0.1));
  }

  private calculateCompleteness(mapping: MappingRules, source: Schema, target: Schema): number {
    const totalSourceColumns = source.tables.reduce((sum, table) => sum + table.columns.length, 0);
    const mappedColumns = mapping.tableMappings.reduce((sum, tm) => sum + tm.columnMappings.length, 0);

    return totalSourceColumns > 0 ? mappedColumns / totalSourceColumns : 0;
  }

  private calculateConsistency(issues: any[]): number {
    const consistencyIssues = issues.filter((i: any) => i.type === 'consistency');
    return Math.max(0, 1 - (consistencyIssues.length * 0.2));
  }

  private findColumnMapping(mapping: MappingRules, sourceColumn:
  string, targetColumn: string): ColumnMapping | undefined {
    for (const tableMapping of mapping.tableMappings) {
      const columnMapping = tableMapping.columnMappings.find(
        cm => cm.sourceColumn === sourceColumn && cm.targetColumn === targetColumn
      );
      if (columnMapping) return columnMapping;
    }
    return undefined;
  }

  private suggestTransformation(issue: any): Transformation {
    return {
      id: crypto.randomUUID(),
      type: 'EXPRESSION',
      expression: 'CAST(${value} AS ' + issue.expectedType + ')',
      parameters: {},
      description: `Convert to ${issue.expectedType}`
    };
  }

  getPreviousMappings(): MappingRules[] {
    return Array.from(this.previousMappings.values());
  }
}