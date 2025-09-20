import { DurableObject } from 'cloudflare:workers';

interface WorkflowState {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  steps: Array<{
    name: string;
    status: string;
    result?: any;
    error?: string;
  }>;
  createdAt: number;
  updatedAt: number;
}

export class WorkflowEngine extends DurableObject {
  private workflows: Map<string, WorkflowState> = new Map();

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'GET' && path === '/workflow') {
      const workflowId = url.searchParams.get('id');
      if (!workflowId) {
        return new Response('Workflow ID required', { status: 400 });
      }

      const workflow = this.workflows.get(workflowId);
      return new Response(JSON.stringify(workflow || null), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'POST' && path === '/workflow') {
      const body = await request.json() as { id: string; steps: any[] };
      const workflow: WorkflowState = {
        id: body.id,
        status: 'pending',
        steps: body.steps.map(step => ({
          name: step.name,
          status: 'pending',
        })),
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };

      this.workflows.set(body.id, workflow);
      return new Response(JSON.stringify(workflow), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method === 'PUT' && path === '/workflow/step') {
      const body = await request.json() as {
        workflowId: string;
        stepName: string;
        status: string;
        result?: any;
        error?: string;
      };

      const workflow = this.workflows.get(body.workflowId);
      if (!workflow) {
        return new Response('Workflow not found', { status: 404 });
      }

      const step = workflow.steps.find(s => s.name === body.stepName);
      if (step) {
        step.status = body.status;
        step.result = body.result;
        step.error = body.error;
      }

      workflow.updatedAt = Date.now();

      const allCompleted = workflow.steps.every(s => s.status === 'completed');
      const anyFailed = workflow.steps.some(s => s.status === 'failed');

      if (allCompleted) {
        workflow.status = 'completed';
      } else if (anyFailed) {
        workflow.status = 'failed';
      } else if (workflow.steps.some(s => s.status === 'running')) {
        workflow.status = 'running';
      }

      this.workflows.set(body.workflowId, workflow);
      return new Response(JSON.stringify(workflow), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Method not allowed', { status: 405 });
  }
}