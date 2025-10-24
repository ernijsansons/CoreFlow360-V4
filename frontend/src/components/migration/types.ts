export interface Migration {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  phase: string;
  startTime?: Date;
  endTime?: Date;
  sourceType: string;
  targetType: string;
  recordsProcessed: number;
  recordsTotal: number;
  errorCount: number;
}
