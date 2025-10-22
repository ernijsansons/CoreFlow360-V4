/**
 * AI Chat Interface
 * Conversational AI for business operations
 */

import { createFileRoute } from '@tanstack/react-router';
import { MainLayout } from '@/layouts/main-layout';
import { RouteErrorFallback } from '@/components/route-error-fallback';
import { ChatInterface } from '@/pages/chat/ChatInterface';

export const Route = createFileRoute('/chat/')({
  component: ChatPage,
  errorComponent: ({ error, reset }) => (
    <MainLayout>
      <RouteErrorFallback error={error} reset={reset} />
    </MainLayout>
  ),
});

function ChatPage() {
  return (
    <MainLayout>
      <ChatInterface />
    </MainLayout>
  );
}
