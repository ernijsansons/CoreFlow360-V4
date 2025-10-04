/**
 * Unified Streaming Response Handler
 * Handles streaming for all agent types
 */

import {
  IAgent,
  AgentTask,
  BusinessContext,
  StreamingChunk,
  StreamingConfig,
  AgentResult
} from './types';
import { Logger } from '../../shared/logger';

export class StreamingHandler {
  private logger: Logger;
  private config: StreamingConfig;

  constructor(config?: Partial<StreamingConfig>) {
    this.logger = new Logger();
    this.config = {
      enabled: true,
      bufferSize: 1024,
      flushInterval: 100,
      compression: false,
      heartbeat: true,
      heartbeatInterval: 30000,
      ...config,
    };
  }

  /**
   * Stream response from any agent type
   */
  async streamResponse(
    agent: IAgent,
    task: AgentTask,
    writer: WritableStreamDefaultWriter<Uint8Array>
  ): Promise<void> {
    const encoder = new TextEncoder();

    try {
      // Send immediate acknowledgment
      await this.writeChunk(writer, {
        type: 'start',
        agentId: agent.id,
        taskId: task.id,
        timestamp: Date.now(),
        metadata: {
          agentType: agent.type,
          capability: task.capability,
          streamingEnabled: this.config.enabled,
        },
      });

      // Route to appropriate streaming method based on agent type
      switch (agent.type) {
        case 'native':
          await this.streamNative(agent, task, writer);
          break;
        case 'external':
          await this.streamExternal(agent, task, writer);
          break;
        case 'specialized':
        case 'custom':
          await this.streamPolling(agent, task, writer);
          break;
        default:
          throw new Error(`Unsupported agent type for streaming: ${agent.type}`);
      }

      // Send completion signal
      await this.writeChunk(writer, {
        type: 'end',
        agentId: agent.id,
        taskId: task.id,
        timestamp: Date.now(),
        metadata: { status: 'completed' },
      });

    } catch (error: any) {
      this.logger.error('Streaming failed', error, {
        agentId: agent.id,
        taskId: task.id,
      });

      // Send error chunk
      await this.writeChunk(writer, {
        type: 'error',
        agentId: agent.id,
        taskId: task.id,
        data: error instanceof Error ? error.message : 'Unknown streaming error',
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Stream from native agents (like Claude)
   */
  private async streamNative(
    agent: IAgent,
    task: AgentTask,
    writer: WritableStreamDefaultWriter<Uint8Array>
  ): Promise<void> {
    // Check if agent supports streaming
    if ('streamResponse' in agent && typeof agent.streamResponse === 'function') {
      const streamMethod
  = agent.streamResponse as (task: AgentTask, context: BusinessContext) => AsyncGenerator<StreamingChunk>;

      try {
        for await (const chunk of streamMethod(task, task.context)) {
          await this.writeChunk(writer, chunk);

          // Add heartbeat if no data for a while
          if (this.config.heartbeat && chunk.type !== 'data') {
            await this.scheduleHeartbeat(writer, agent.id, task.id);
          }
        }
      } catch (error: any) {
        throw new Error(`Native streaming failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    } else {
      // Fallback to non-streaming execution with chunked response
      await this.streamFallback(agent, task, writer);
    }
  }

  /**
   * Stream from external agents via webhooks
   */
  private async streamExternal(
    agent: IAgent,
    task: AgentTask,
    writer: WritableStreamDefaultWriter<Uint8Array>
  ): Promise<void> {
    // For external agents, we need to make HTTP requests and handle webhook responses
    const agentConfig = this.getAgentConfig(agent);

    if (!agentConfig?.webhookUrl) {
      throw new Error('External agent requires webhook URL for streaming');
    }

    try {
      // Start the external task
      const response = await fetch(agentConfig.apiEndpoint || agentConfig.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${agentConfig.apiKey}`,
          ...agentConfig.headers,
        },
        body: JSON.stringify({
          task: {
            id: task.id,
            capability: task.capability,
            input: task.input,
            context: task.context,
          },
          streaming: true,
          webhookUrl: `${agentConfig.webhookUrl}/stream/${task.id}`,
        }),
      });

      if (!response.ok) {
        throw new Error(`External agent request failed: ${response.status} ${response.statusText}`);
      }

      // Poll for streaming updates
      await this.pollExternalStream(task.id, agentConfig.webhookUrl, writer, agent.id);

    } catch (error: any) {
      throw new Error(`External streaming failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Stream using polling for specialized agents
   */
  private async streamPolling(
    agent: IAgent,
    task: AgentTask,
    writer: WritableStreamDefaultWriter<Uint8Array>
  ): Promise<void> {
    const maxPollAttempts = 300; // 5 minutes with 1-second intervals
    let pollAttempts = 0;

    try {
      // Start the task execution
      const executionPromise = agent.execute(task, task.context);

      // Poll for progress updates
      while (pollAttempts < maxPollAttempts) {
        pollAttempts++;

        // Check if execution is complete
        const isComplete = await Promise.race([
          executionPromise.then(() => true),
          new Promise(resolve => setTimeout(() => resolve(false), 1000)),
        ]);

        if (isComplete) {
          const result = await executionPromise;
          await this.writeChunk(writer, {
            type: 'data',
            agentId: agent.id,
            taskId: task.id,
            data: result,
            timestamp: Date.now(),
            metadata: { final: true },
          });
          break;
        }

        // Send progress update
        await this.writeChunk(writer, {
          type: 'data',
          agentId: agent.id,
          taskId: task.id,
          data: { progress: `Processing... (${pollAttempts}/${maxPollAttempts})` },
          timestamp: Date.now(),
          metadata: { progress: pollAttempts / maxPollAttempts },
        });

        // Send heartbeat
        if (this.config.heartbeat && pollAttempts % 30 === 0) {
          await this.scheduleHeartbeat(writer, agent.id, task.id);
        }
      }

      if (pollAttempts >= maxPollAttempts) {
        throw new Error('Polling timeout exceeded');
      }

    } catch (error: any) {
      throw new Error(`Polling streaming failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Fallback streaming for non-streaming agents
   */
  private async streamFallback(
    agent: IAgent,
    task: AgentTask,
    writer: WritableStreamDefaultWriter<Uint8Array>
  ): Promise<void> {
    try {
      // Execute the task normally
      const result = await agent.execute(task, task.context);

      // Stream the result in chunks
      const resultText = typeof result.data === 'string'
        ? result.data
        : JSON.stringify(result.data, null, 2);

      const chunkSize = this.config.bufferSize;
      for (let i = 0; i < resultText.length; i += chunkSize) {
        const chunk = resultText.slice(i, i + chunkSize);

        await this.writeChunk(writer, {
          type: 'data',
          agentId: agent.id,
          taskId: task.id,
          data: chunk,
          timestamp: Date.now(),
          metadata: {
            progress: (i + chunk.length) / resultText.length,
            chunkIndex: Math.floor(i / chunkSize),
          },
        });

        // Small delay to simulate streaming
        await new Promise(resolve => setTimeout(resolve, this.config.flushInterval));
      }

    } catch (error: any) {
      throw new Error(`Fallback streaming failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Poll external webhook for streaming updates
   */
  private async pollExternalStream(
    taskId: string,
    webhookUrl: string,
    writer: WritableStreamDefaultWriter<Uint8Array>,
    agentId: string
  ): Promise<void> {
    const maxPollAttempts = 300;
    let pollAttempts = 0;

    while (pollAttempts < maxPollAttempts) {
      pollAttempts++;

      try {
        const response = await fetch(`${webhookUrl}/stream/${taskId}/status`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });

        if (response.ok) {
          const data = await response.json() as any;

          if (data.chunks) {
            // Send all available chunks
            for (const chunk of data.chunks) {
              await this.writeChunk(writer, {
                type: 'data',
                agentId,
                taskId,
                data: chunk.data,
                timestamp: chunk.timestamp || Date.now(),
                metadata: chunk.metadata,
              });
            }
          }

          if (data.status === 'completed' || data.status === 'failed') {
            break;
          }
        }

        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, 1000));

      } catch (error: any) {
        this.logger.warn('External stream poll failed', error, { taskId, pollAttempts });
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    if (pollAttempts >= maxPollAttempts) {
      throw new Error('External stream polling timeout');
    }
  }

  /**
   * Write a streaming chunk to the response
   */
  private async writeChunk(
    writer: WritableStreamDefaultWriter<Uint8Array>,
    chunk: StreamingChunk
  ): Promise<void> {
    const encoder = new TextEncoder();

    try {
      // Format as Server-Sent Events
      const data = JSON.stringify(chunk);
      const sseChunk = `data: ${data}\n\n`;

      await writer.write(encoder.encode(sseChunk));

      this.logger.debug('Streaming chunk sent', {
        type: chunk.type,
        agentId: chunk.agentId,
        taskId: chunk.taskId,
        dataSize: data.length,
      });

    } catch (error: any) {
      this.logger.error('Failed to write streaming chunk', error, {
        chunkType: chunk.type,
        agentId: chunk.agentId,
        taskId: chunk.taskId,
      });
      throw error;
    }
  }

  /**
   * Schedule a heartbeat message
   */
  private async scheduleHeartbeat(
    writer: WritableStreamDefaultWriter<Uint8Array>,
    agentId: string,
    taskId: string
  ): Promise<void> {
    setTimeout(async () => {
      try {
        await this.writeChunk(writer, {
          type: 'data',
          agentId,
          taskId,
          data: { heartbeat: true },
          timestamp: Date.now(),
          metadata: { heartbeat: true },
        });
      } catch (error: any) {
        this.logger.warn('Heartbeat failed', error, { agentId, taskId });
      }
    }, this.config.heartbeatInterval);
  }

  /**
   * Get agent configuration (placeholder for actual config retrieval)
   */
  private getAgentConfig(agent: IAgent): any {
    // In a real implementation, this would retrieve agent configuration
    // from the registry or configuration store
    return {
      apiEndpoint: `https://api.example.com/agents/${agent.id}`,
      webhookUrl: `https://webhooks.example.com/agents/${agent.id}`,
      apiKey: process.env.EXTERNAL_AGENT_API_KEY,
      headers: {
        'User-Agent': 'CoreFlow360-Agent-System/1.0',
      },
    };
  }

  /**
   * Create a streaming response for Cloudflare Workers
   */
  static createStreamingResponse(
    handler: StreamingHandler,
    agent: IAgent,
    task: AgentTask
  ): Response {
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();

    // Start streaming in the background
    handler.streamResponse(agent, task, writer)
      .catch((error: any) => {
      })
      .finally(() => {
        writer.close();
      });

    return new Response(readable, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });
  }

  /**
   * Get streaming configuration
   */
  getConfig(): StreamingConfig {
    return { ...this.config };
  }

  /**
   * Update streaming configuration
   */
  updateConfig(newConfig: Partial<StreamingConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.logger.info('Streaming configuration updated', this.config);
  }
}