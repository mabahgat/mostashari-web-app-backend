import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MessageBubble } from '../MessageBubble';
import { Message } from '../../api/client';

describe('MessageBubble', () => {
  const mockTimestamp = '2024-01-01T12:34:56.000Z';

  describe('user messages', () => {
    it('should render user message with correct styling', () => {
      const message: Message = {
        role: 'user',
        content: 'Hello AI',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const content = screen.getByText('Hello AI');
      expect(content).toBeInTheDocument();

      // User message should have specific styling
      expect(content).toHaveClass('bg-indigo-600');
      expect(content).toHaveClass('text-white');
    });

    it('should display user avatar', () => {
      const message: Message = {
        role: 'user',
        content: 'Test',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const avatar = screen.getByText('You');
      expect(avatar).toBeInTheDocument();
      expect(avatar.parentElement).toHaveClass('bg-indigo-100');
    });

    it('should show timestamp for user messages', () => {
      const message: Message = {
        role: 'user',
        content: 'Test',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      // Timestamp should be in format HH:MM (locale-dependent)
      const timestamp = screen.getByText(/\d{1,2}:\d{2}/);
      expect(timestamp).toBeInTheDocument();
    });

    it('should render multiline user messages', () => {
      const message: Message = {
        role: 'user',
        content: 'Line 1\nLine 2\nLine 3',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const content = screen.getByText('Line 1\nLine 2\nLine 3');
      expect(content).toBeInTheDocument();
      expect(content).toHaveClass('whitespace-pre-wrap');
    });
  });

  describe('assistant messages', () => {
    it('should render assistant message with correct styling', () => {
      const message: Message = {
        role: 'assistant',
        content: 'Hello User',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const content = screen.getByText('Hello User');
      expect(content).toBeInTheDocument();

      // Assistant message should have different styling
      expect(content).toHaveClass('bg-white');
      expect(content).toHaveClass('text-slate-700');
    });

    it('should display AI avatar', () => {
      const message: Message = {
        role: 'assistant',
        content: 'Test',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const avatar = screen.getByText('AI');
      expect(avatar).toBeInTheDocument();
      expect(avatar.parentElement).toHaveClass('bg-violet-100');
    });

    it('should show timestamp for assistant messages', () => {
      const message: Message = {
        role: 'assistant',
        content: 'Test',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const timestamp = screen.getByText(/\d{1,2}:\d{2}/);
      expect(timestamp).toBeInTheDocument();
    });

    it('should render multiline assistant messages', () => {
      const message: Message = {
        role: 'assistant',
        content: 'Response line 1\nResponse line 2',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const content = screen.getByText('Response line 1\nResponse line 2');
      expect(content).toBeInTheDocument();
    });
  });

  describe('layout', () => {
    it('should align user messages to the right', () => {
      const message: Message = {
        role: 'user',
        content: 'Test',
        timestamp: mockTimestamp,
      };

      const { container } = render(<MessageBubble message={message} />);

      const wrapper = container.firstChild as HTMLElement;
      expect(wrapper).toHaveClass('justify-end');
    });

    it('should align assistant messages to the left', () => {
      const message: Message = {
        role: 'assistant',
        content: 'Test',
        timestamp: mockTimestamp,
      };

      const { container } = render(<MessageBubble message={message} />);

      const wrapper = container.firstChild as HTMLElement;
      expect(wrapper).toHaveClass('justify-start');
    });

    it('should limit message width to 75%', () => {
      const message: Message = {
        role: 'user',
        content: 'Test',
        timestamp: mockTimestamp,
      };

      const { container } = render(<MessageBubble message={message} />);

      const messageContainer = container.querySelector('.max-w-\\[75\\%\\]');
      expect(messageContainer).toBeInTheDocument();
    });
  });

  describe('content handling', () => {
    it('should handle empty content', () => {
      const message: Message = {
        role: 'user',
        content: '',
        timestamp: mockTimestamp,
      };

      const { container } = render(<MessageBubble message={message} />);

      expect(container.querySelector('.px-4')).toBeInTheDocument();
    });

    it('should handle very long content', () => {
      const longContent = 'A'.repeat(1000);
      const message: Message = {
        role: 'user',
        content: longContent,
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      const content = screen.getByText(longContent);
      expect(content).toBeInTheDocument();
      expect(content).toHaveClass('break-words');
    });

    it('should handle special characters in content', () => {
      const message: Message = {
        role: 'user',
        content: '<script>alert("xss")</script>',
        timestamp: mockTimestamp,
      };

      render(<MessageBubble message={message} />);

      // Content should be escaped (rendered as text, not HTML)
      const content = screen.getByText('<script>alert("xss")</script>');
      expect(content).toBeInTheDocument();
    });
  });

  describe('timestamp formatting', () => {
    it('should format timestamp correctly', () => {
      const message: Message = {
        role: 'user',
        content: 'Test',
        timestamp: '2024-01-01T14:30:00.000Z',
      };

      render(<MessageBubble message={message} />);

      // Should show time in HH:MM format (locale-dependent)
      const timeElement = screen.getByText(/\d{1,2}:\d{2}/);
      expect(timeElement).toBeInTheDocument();
      expect(timeElement).toHaveClass('text-xs');
      expect(timeElement).toHaveClass('text-slate-400');
    });
  });
});
