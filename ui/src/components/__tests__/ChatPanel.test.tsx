import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ChatPanel } from '../ChatPanel';
import { createClient } from '../../api/client';

// Mock the createClient function
vi.mock('../../api/client', () => ({
  createClient: vi.fn(),
  ApiClientError: class ApiClientError extends Error {
    constructor(public status: number, public apiError: { code: string; message: string }) {
      super(apiError.message);
    }
  },
}));

describe('ChatPanel', () => {
  let mockClient: any;
  const mockApiKey = 'test-api-key';
  const mockOnSessionUpdate = vi.fn();

  beforeEach(() => {
    mockClient = {
      getSession: vi.fn(),
      sendMessage: vi.fn(),
    };

    (createClient as any).mockReturnValue(mockClient);

    // Mock scrollIntoView
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('no session selected', () => {
    it('should display empty state when sessionId is null', () => {
      render(
        <ChatPanel sessionId={null} apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      expect(screen.getByText('💬')).toBeInTheDocument();
      expect(screen.getByText('Select or create a session')).toBeInTheDocument();
      expect(screen.getByText('Start a conversation with Azure AI Foundry')).toBeInTheDocument();
    });

    it('should not call getSession when sessionId is null', () => {
      render(
        <ChatPanel sessionId={null} apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      expect(mockClient.getSession).not.toHaveBeenCalled();
    });
  });

  describe('session loading', () => {
    it('should load session details when sessionId changes', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'test-client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        historyLength: 0,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => {
        expect(mockClient.getSession).toHaveBeenCalledWith('session-123');
      });

      expect(screen.getByText('test-client')).toBeInTheDocument();
      expect(screen.getByText('session-123')).toBeInTheDocument();
    });

    it('should display previous messages when session loads', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 2,
        historyLength: 2,
        recentMessages: [
          { role: 'user' as const, content: 'Hello', timestamp: '2024-01-01T00:00:00.000Z' },
          { role: 'assistant' as const, content: 'Hi there', timestamp: '2024-01-01T00:00:01.000Z' },
        ],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => {
        expect(screen.getByText('Hello')).toBeInTheDocument();
        expect(screen.getByText('Hi there')).toBeInTheDocument();
      });
    });

    it('should handle session loading error', async () => {
      const { ApiClientError } = await import('../../api/client');
      const error = new (ApiClientError as any)(404, { code: 'NOT_FOUND', message: 'Session not found' });
      mockClient.getSession.mockRejectedValue(error);

      render(
        <ChatPanel sessionId="session-404" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => {
        expect(screen.getByText('Session not found')).toBeInTheDocument();
      });
    });

    it('should handle non-ApiClientError loading errors', async () => {
      mockClient.getSession.mockRejectedValue(new Error('Network error'));

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => {
        expect(screen.getByText('Failed to load session')).toBeInTheDocument();
      });
    });

    it('should clear messages when sessionId changes to null', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 1,
        historyLength: 1,
        recentMessages: [
          { role: 'user' as const, content: 'Test', timestamp: '2024-01-01T00:00:00.000Z' },
        ],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      const { rerender } = render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => {
        expect(screen.getByText('Test')).toBeInTheDocument();
      });

      // Change to null session
      rerender(
        <ChatPanel sessionId={null} apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      expect(screen.queryByText('Test')).not.toBeInTheDocument();
      expect(screen.getByText('Select or create a session')).toBeInTheDocument();
    });
  });

  describe('sending messages', () => {
    beforeEach(async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        historyLength: 0,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);
    });

    it('should send message when send button is clicked', async () => {
      mockClient.sendMessage.mockResolvedValue({
        sessionId: 'session-123',
        reply: 'AI response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, 'Hello AI');
      fireEvent.click(sendButton);

      await waitFor(() => {
        expect(mockClient.sendMessage).toHaveBeenCalledWith('session-123', 'Hello AI');
      });

      await waitFor(() => {
        expect(screen.getByText('Hello AI')).toBeInTheDocument();
        expect(screen.getByText('AI response')).toBeInTheDocument();
      });

      expect(mockOnSessionUpdate).toHaveBeenCalled();
    });

    it('should send message when Enter key is pressed', async () => {
      mockClient.sendMessage.mockResolvedValue({
        sessionId: 'session-123',
        reply: 'Response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);

      await userEvent.type(textarea, 'Test{Enter}');

      await waitFor(() => {
        expect(mockClient.sendMessage).toHaveBeenCalledWith('session-123', 'Test');
      });
    });

    it('should not send message when Shift+Enter is pressed', async () => {
      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);

      await userEvent.type(textarea, 'Line 1{Shift>}{Enter}Line 2');

      expect(mockClient.sendMessage).not.toHaveBeenCalled();
      expect(textarea).toHaveValue('Line 1\nLine 2');
    });

    it('should not send empty messages', async () => {
      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, '   '); // Only spaces
      fireEvent.click(sendButton);

      expect(mockClient.sendMessage).not.toHaveBeenCalled();
    });

    it('should trim whitespace from messages', async () => {
      mockClient.sendMessage.mockResolvedValue({
        sessionId: 'session-123',
        reply: 'Response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, '  Hello  ');
      fireEvent.click(sendButton);

      await waitFor(() => {
        expect(mockClient.sendMessage).toHaveBeenCalledWith('session-123', 'Hello');
      });
    });

    it('should clear input after sending message', async () => {
      mockClient.sendMessage.mockResolvedValue({
        sessionId: 'session-123',
        reply: 'Response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, 'Test message');
      fireEvent.click(sendButton);

      expect(textarea).toHaveValue('');
    });

    it('should show typing indicator while waiting for response', async () => {
      let resolveMessage: any;
      const messagePromise = new Promise((resolve) => {
        resolveMessage = resolve;
      });

      mockClient.sendMessage.mockReturnValue(messagePromise);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, 'Test');
      fireEvent.click(sendButton);

      await waitFor(() => {
        const dots = screen.getAllByRole('none', { hidden: true });
        expect(dots.length).toBeGreaterThanOrEqual(3);
      });

      resolveMessage({
        sessionId: 'session-123',
        reply: 'Response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      await waitFor(() => {
        expect(screen.queryByRole('none', { hidden: true })).not.toBeInTheDocument();
      });
    });

    it('should disable input while sending', async () => {
      let resolveMessage: any;
      const messagePromise = new Promise((resolve) => {
        resolveMessage = resolve;
      });

      mockClient.sendMessage.mockReturnValue(messagePromise);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, 'Test');
      fireEvent.click(sendButton);

      await waitFor(() => {
        expect(textarea).toBeDisabled();
        expect(sendButton).toBeDisabled();
      });

      resolveMessage({
        sessionId: 'session-123',
        reply: 'Response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      await waitFor(() => {
        expect(textarea).not.toBeDisabled();
        expect(sendButton).not.toBeDisabled();
      });
    });

    it('should handle send message error', async () => {
      const { ApiClientError } = await import('../../api/client');
      const error = new (ApiClientError as any)(502, {
        code: 'UPSTREAM_ERROR',
        message: 'Azure service error',
      });
      mockClient.sendMessage.mockRejectedValue(error);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate=  {mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, 'Test');
      fireEvent.click(sendButton);

      await waitFor(() => {
        expect(screen.getByText('Azure service error')).toBeInTheDocument();
      });

      // User message should be removed
      expect(screen.queryByText('Test')).not.toBeInTheDocument();
    });

    it('should handle non-ApiClientError send errors', async () => {
      mockClient.sendMessage.mockRejectedValue(new Error('Network failure'));

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      const sendButton = screen.getByRole('button');

      await userEvent.type(textarea, 'Test');
      fireEvent.click(sendButton);

      await waitFor(() => {
        expect(screen.getByText('Failed to send message')).toBeInTheDocument();
      });
    });
  });

  describe('error display', () => {
    it('should display error banner when error exists', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        historyLength: 0,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      const { ApiClientError } = await import('../../api/client');
      const error = new (ApiClientError as any)(500, { code: 'ERROR', message: 'Test error' });
      mockClient.sendMessage.mockRejectedValue(error);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      await userEvent.type(textarea, 'Test{Enter}');

      await waitFor(() => {
        expect(screen.getByText('Test error')).toBeInTheDocument();
      });
    });

    it('should close error banner when × button is clicked', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        historyLength: 0,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      const { ApiClientError } = await import('../../api/client');
      const error = new (ApiClientError as any)(500, { code: 'ERROR', message: 'Test error' });
      mockClient.sendMessage.mockRejectedValue(error);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      await userEvent.type(textarea, 'Test{Enter}');

      await waitFor(() => {
        expect(screen.getByText('Test error')).toBeInTheDocument();
      });

      const closeButton = screen.getByRole('button', { name: '×' });
      fireEvent.click(closeButton);

      expect(screen.queryByText('Test error')).not.toBeInTheDocument();
    });

    it('should clear error when sending new message', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        historyLength: 0,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      const { ApiClientError } = await import('../../api/client');
      const error = new (ApiClientError as any)(500, { code: 'ERROR', message: 'First error' });
      mockClient.sendMessage.mockRejectedValueOnce(error);
      mockClient.sendMessage.mockResolvedValueOnce({
        sessionId: 'session-123',
        reply: 'Success',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      await userEvent.type(textarea, 'Test1{Enter}');

      await waitFor(() => {
        expect(screen.getByText('First error')).toBeInTheDocument();
      });

      await userEvent.type(textarea, 'Test2{Enter}');

      await waitFor(() => {
        expect(screen.queryByText('First error')).not.toBeInTheDocument();
      });
    });
  });

  describe('UI state', () => {
    it('should display session info in header', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'test-client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 5,
        historyLength: 5,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => {
        expect(screen.getByText('test-client')).toBeInTheDocument();
        expect(screen.getByText('session-123')).toBeInTheDocument();
        expect(screen.getByText('5 messages')).toBeInTheDocument();
        expect(screen.getByText('active')).toBeInTheDocument();
      });
    });

    it('should show empty conversation prompt when no messages', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        historyLength: 0,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => {
        expect(screen.getByText('Send a message to begin the conversation.')).toBeInTheDocument();
      });
    });

    it('should auto-scroll to bottom when messages change', async () => {
      const mockSession = {
        id: 'session-123',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'active' as const,
        messageCount: 0,
        historyLength: 0,
        recentMessages: [],
      };

      mockClient.getSession.mockResolvedValue(mockSession);
      mockClient.sendMessage.mockResolvedValue({
        sessionId: 'session-123',
        reply: 'Response',
        messageCount: 2,
        lastActivityAt: '2024-01-01T00:01:00.000Z',
      });

      render(
        <ChatPanel sessionId="session-123" apiKey={mockApiKey} onSessionUpdate={mockOnSessionUpdate} />
      );

      await waitFor(() => { expect(mockClient.getSession).toHaveBeenCalled(); });

      const textarea = screen.getByPlaceholderText(/Type a message/);
      await userEvent.type(textarea, 'Test{Enter}');

      await waitFor(() => {
        expect(Element.prototype.scrollIntoView).toHaveBeenCalled();
      });
    });
  });
});
