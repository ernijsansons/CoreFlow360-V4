import { Context, Next } from 'hono';
import { CORSUtils } from '../utils/cors-utils';

export interface ProxyConfig {
  target: string;
  changeOrigin?: boolean;
  rewrite?: (path: string) => string;
  headers?: Record<string, string>;
  timeout?: number;
}

export class AgentProxy {
  private config: ProxyConfig;

  constructor(config: ProxyConfig) {
    this.config = {
      changeOrigin: true,
      timeout: 30000,
      ...config
    };
  }

  /**
   * Middleware to proxy requests to the agent system
   */
  middleware() {
    return async (c: Context, next: Next) => {
      const originalPath = c.req.path;
      const targetPath = this.config.rewrite ? this.config.rewrite(originalPath) : originalPath;
      const targetUrl = `${this.config.target}${targetPath}`;

      try {
        // Build headers
        const headers = new Headers(c.req.raw.headers);

        // Add custom headers if specified
        if (this.config.headers) {
          Object.entries(this.config.headers).forEach(([key, value]) => {
            headers.set(key, value);
          });
        }

        // Update host header if changeOrigin is true
        if (this.config.changeOrigin) {
          const targetHost = new URL(this.config.target).host;
          headers.set('Host', targetHost);
        }

        // Add X-Forwarded headers
      
   headers.set('X-Forwarded-For', c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown');
        headers.set('X-Forwarded-Proto', c.req.header('X-Forwarded-Proto') || 'http');
        headers.set('X-Forwarded-Host', c.req.header('Host') || 'localhost');

        // Create abort controller for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout!);

        // Forward the request
        const response = await fetch(targetUrl, {
          method: c.req.method,
          headers,
          body: c.req.method !== 'GET' && c.req.method !== 'HEAD'
            ? await c.req.raw.arrayBuffer()
            : undefined,
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        // Return the proxied response
        const responseHeaders = new Headers(response.headers);

        // Remove hop-by-hop headers
        ['Connection', 'Keep-Alive', 'Transfer-Encoding', 'TE', 'Trailer', 'Upgrade'].forEach(header => {
          responseHeaders.delete(header);
        });

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders
        });
      } catch (error) {

        if ((error as any).name === 'AbortError') {
          return c.json({
            error: 'Gateway Timeout',
            message: 'Request to agent system timed out',
            target: targetUrl
          }, 504);
        }

        return c.json({
          error: 'Bad Gateway',
          message: 'Failed to reach agent system',
          details: error instanceof Error ? error.message : 'Unknown error'
        }, 502);
      }
    };
  }

  /**
   * WebSocket proxy for real-time communication
   */
  websocketProxy() {
    return async (c: Context) => {
      const upgradeHeader = c.req.header('Upgrade');
      if (!upgradeHeader || upgradeHeader !== 'websocket') {
        return c.json({ error: 'Expected WebSocket' }, 426);
      }

      try {
        // Create WebSocket connection to target
        const targetUrl = this.config.target.replace('http', 'ws') + '/ws';
        const targetWs = new WebSocket(targetUrl);

        // Get the client WebSocket
        const { response, socket: clientWs } = Deno.upgradeWebSocket(c.req.raw);

        // Bi-directional message forwarding
        clientWs.onmessage = (event) => {
          if (targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(event.data);
          }
        };

        targetWs.onmessage = (event) => {
          if (clientWs.readyState === WebSocket.OPEN) {
            clientWs.send(event.data);
          }
        };

        // Handle connection events
        clientWs.onopen = () => {
        };

        targetWs.onopen = () => {
        };

        // Handle errors and closing
        clientWs.onerror = (error) => {
          targetWs.close();
        };

        targetWs.onerror = (error) => {
          clientWs.close();
        };

        clientWs.onclose = () => {
          targetWs.close();
        };

        targetWs.onclose = () => {
          clientWs.close();
        };

        return response;
      } catch (error) {
        return c.json({
          error: 'WebSocket Proxy Failed',
          message: error instanceof Error ? error.message : 'Unknown error'
        }, 502);
      }
    };
  }

  /**
   * Server-Sent Events proxy for streaming data
   */
  sseProxy() {
    return async (c: Context) => {
      const targetUrl = `${this.config.target}/stream`;

      try {
        const response = await fetch(targetUrl, {
          headers: {
            'Accept': 'text/event-stream',
            'Cache-Control': 'no-cache'
          }
        });

        if (!response.ok) {
          throw new Error(`SSE proxy failed: ${response.statusText}`);
        }

        // Forward the SSE stream
        return new Response(response.body, {
          headers: (() => {
            const headers: Record<string, string> = {
              'Content-Type': 'text/event-stream',
              'Cache-Control': 'no-cache',
              'Connection': 'keep-alive'
            };

            // CRITICAL: Secure CORS headers with origin validation
            const origin = c.req.header('Origin') || c.req.header('origin');
            CORSUtils.setCORSHeaders(headers, origin, { environment: c.env?.ENVIRONMENT });

            return headers;
          })()
        });
      } catch (error) {
        return c.json({
          error: 'SSE Proxy Failed',
          message: error instanceof Error ? error.message : 'Unknown error'
        }, 502);
      }
    };
  }
}

// Factory function for creating proxy middleware
export function createAgentProxy(config: ProxyConfig) {
  return new AgentProxy(config);
}

// Pre-configured proxy for the agent system
export const agentSystemProxy = createAgentProxy({
  target: process.env.AGENT_SYSTEM_URL || 'http://localhost:3000',
  changeOrigin: true,
  headers: {
    'X-Proxy-Source': 'CoreFlow360'
  },
  timeout: 30000
});