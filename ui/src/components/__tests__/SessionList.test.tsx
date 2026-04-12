import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { SessionList } from '../SessionList';
import { SessionSummary } from '../../api/client';

describe('SessionList', () => {
  const mockSessions: SessionSummary[] = [
    {
      id: 'session-1',
      clientName: 'client1',
      createdAt: '2024-01-01T00:00:00.000Z',
      lastActivityAt: '2024-01-01T12:00:00.000Z',
      status: 'active',
      messageCount: 5,
    },
    {
      id: 'session-2',
      clientName: 'client2',
      createdAt: '2024-01-01T01:00:00.000Z',
      lastActivityAt: '2024-01-01T13:00:00.000Z',
      status: 'active',
      messageCount: 10,
    },
  ];

  const defaultProps = {
    sessions: mockSessions,
    activeSessionId: null,
    onSelect: vi.fn(),
    onCreate: vi.fn(),
    onDelete: vi.fn(),
    loading: false,
  };

  describe('rendering', () => {
    it('should render session list with all sessions', () => {
      render(<SessionList {...defaultProps} />);

      expect(screen.getByText('Sessions')).toBeInTheDocument();
      expect(screen.getByText('client1')).toBeInTheDocument();
      expect(screen.getByText('client2')).toBeInTheDocument();
    });

    it('should display empty state when no sessions exist', () => {
      render(<SessionList {...defaultProps} sessions={[]} />);

      expect(screen.getByText(/No sessions yet/)).toBeInTheDocument();
      expect(screen.getByText(/Click.*New Session.*to start chatting/)).toBeInTheDocument();
    });

    it('should not display empty state when loading', () => {
      render(<SessionList {...defaultProps} sessions={[]} loading={true} />);

      expect(screen.queryByText(/No sessions yet/)).not.toBeInTheDocument();
    });

    it('should render session details correctly', () => {
      render(<SessionList {...defaultProps} />);

      // Check for client name
      expect(screen.getByText('client1')).toBeInTheDocument();

      // Check for truncated session ID
      expect(screen.getByText(/session-1/)).toBeInTheDocument();

      // Check for message count
      expect(screen.getByText(/5 msgs/)).toBeInTheDocument();

      // Check for status badge
      const statusBadges = screen.getAllByText('active');
      expect(statusBadges.length).toBeGreaterThan(0);
    });

    it('should singular "msg" for single message', () => {
      const singleMsgSession: SessionSummary[] = [{
        id: 'session-1',
        clientName: 'client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T12:00:00.000Z',
        status: 'active',
        messageCount: 1,
      }];

      render(<SessionList {...defaultProps} sessions={singleMsgSession} />);

      expect(screen.getByText(/1 msg\b/)).toBeInTheDocument();
    });

    it('should highlight active session', () => {
      render(<SessionList {...defaultProps} activeSessionId="session-1" />);

      const sessionElements = screen.getAllByRole('button', { name: /×/ })[0]
        .closest('.group') as HTMLElement;

      expect(sessionElements).toHaveClass('bg-indigo-50');
      expect(sessionElements).toHaveClass('border-indigo-200');
    });

    it('should not highlight inactive sessions', () => {
      render(<SessionList {...defaultProps} activeSessionId="session-1" />);

      const allSessions = screen.getAllByRole('button', { name: /×/ });
      const inactiveSession = allSessions[1].closest('.group') as HTMLElement;

      expect(inactiveSession).not.toHaveClass('bg-indigo-50');
    });
  });

  describe('new session button', () => {
    it('should call onCreate when clicked', () => {
      const onCreate = vi.fn();
      render(<SessionList {...defaultProps} onCreate={onCreate} />);

      const newButton = screen.getByRole('button', { name: /New Session/i });
      fireEvent.click(newButton);

      expect(onCreate).toHaveBeenCalledTimes(1);
    });

    it('should be disabled when loading', () => {
      render(<SessionList {...defaultProps} loading={true} />);

      const newButton = screen.getByRole('button', { name: /New Session/i });
      expect(newButton).toBeDisabled();
      expect(newButton).toHaveClass('disabled:opacity-50');
    });

    it('should be enabled when not loading', () => {
      render(<SessionList {...defaultProps} loading={false} />);

      const newButton = screen.getByRole('button', { name: /New Session/i });
      expect(newButton).not.toBeDisabled();
    });
  });

  describe('session selection', () => {
    it('should call onSelect when session is clicked', () => {
      const onSelect = vi.fn();
      render(<SessionList {...defaultProps} onSelect={onSelect} />);

      const session = screen.getByText('client1').closest('.group') as HTMLElement;
      fireEvent.click(session);

      expect(onSelect).toHaveBeenCalledWith('session-1');
    });

    it('should call onSelect for different sessions', () => {
      const onSelect = vi.fn();
      render(<SessionList {...defaultProps} onSelect={onSelect} />);

      const session2 = screen.getByText('client2').closest('.group') as HTMLElement;
      fireEvent.click(session2);

      expect(onSelect).toHaveBeenCalledWith('session-2');
    });
  });

  describe('session deletion', () => {
    it('should call onDelete when delete button is clicked', () => {
      const onDelete = vi.fn();
      render(<SessionList {...defaultProps} onDelete={onDelete} />);

      const deleteButtons = screen.getAllByRole('button', { name: /×/ });
      fireEvent.click(deleteButtons[0]);

      expect(onDelete).toHaveBeenCalledWith('session-1');
    });

    it('should not trigger onSelect when delete is clicked', () => {
      const onSelect = vi.fn();
      const onDelete = vi.fn();
      render(<SessionList {...defaultProps} onSelect={onSelect} onDelete={onDelete} />);

      const deleteButtons = screen.getAllByRole('button', { name: /×/ });
      fireEvent.click(deleteButtons[0]);

      expect(onDelete).toHaveBeenCalledWith('session-1');
      expect(onSelect).not.toHaveBeenCalled();
    });

    it('should have delete button on each session', () => {
      render(<SessionList {...defaultProps} />);

      const deleteButtons = screen.getAllByRole('button', { name: /×/ });
      expect(deleteButtons).toHaveLength(mockSessions.length);
    });
  });

  describe('status display', () => {
    it('should show active status with green styling', () => {
      render(<SessionList {...defaultProps} />);

      const activeBadges = screen.getAllByText('active');
      activeBadges.forEach((badge) => {
        expect(badge).toHaveClass('bg-emerald-50');
        expect(badge).toHaveClass('text-emerald-700');
      });
    });

    it('should show expired status with gray styling', () => {
      const expiredSessions: SessionSummary[] = [{
        id: 'session-expired',
        clientName: 'expired-client',
        createdAt: '2024-01-01T00:00:00.000Z',
        lastActivityAt: '2024-01-01T00:00:00.000Z',
        status: 'expired',
        messageCount: 0,
      }];

      render(<SessionList {...defaultProps} sessions={expiredSessions} />);

      const expiredBadge = screen.getByText('expired');
      expect(expiredBadge).toHaveClass('bg-slate-100');
      expect(expiredBadge).toHaveClass('text-slate-500');
    });
  });

  describe('time display', () => {
    it('should display relative time for recent activity', () => {
      const recentSession: SessionSummary[] = [{
        id: 'session-1',
        clientName: 'client',
        createdAt: new Date(Date.now() - 30000).toISOString(), // 30 seconds ago
        lastActivityAt: new Date(Date.now() - 30000).toISOString(),
        status: 'active',
        messageCount: 1,
      }];

      render(<SessionList {...defaultProps} sessions={recentSession} />);

      expect(screen.getByText(/just now/i)).toBeInTheDocument();
    });

    it('should display minutes ago', () => {
      const session: SessionSummary[] = [{
        id: 'session-1',
        clientName: 'client',
        createdAt: new Date(Date.now() - 300000).toISOString(), // 5 minutes ago
        lastActivityAt: new Date(Date.now() - 300000).toISOString(),
        status: 'active',
        messageCount: 1,
      }];

      render(<SessionList {...defaultProps} sessions={session} />);

      expect(screen.getByText(/\d+m ago/)).toBeInTheDocument();
    });

    it('should display hours ago', () => {
      const session: SessionSummary[] = [{
        id: 'session-1',
        clientName: 'client',
        createdAt: new Date(Date.now() - 7200000).toISOString(), // 2 hours ago
        lastActivityAt: new Date(Date.now() - 7200000).toISOString(),
        status: 'active',
        messageCount: 1,
      }];

      render(<SessionList {...defaultProps} sessions={session} />);

      expect(screen.getByText(/\d+h ago/)).toBeInTheDocument();
    });

    it('should display days ago', () => {
      const session: SessionSummary[] = [{
        id: 'session-1',
        clientName: 'client',
        createdAt: new Date(Date.now() - 172800000).toISOString(), // 2 days ago
        lastActivityAt: new Date(Date.now() - 172800000).toISOString(),
        status: 'active',
        messageCount: 1,
      }];

      render(<SessionList {...defaultProps} sessions={session} />);

      expect(screen.getByText(/\d+d ago/)).toBeInTheDocument();
    });
  });

  describe('session ID display', () => {
    it('should truncate long session IDs', () => {
      render(<SessionList {...defaultProps} />);

      // IDs should be truncated and show ellipsis
      const truncatedIds = screen.getAllByText(/session-\d…/);
      expect(truncatedIds.length).toBeGreaterThan(0);
    });
  });
});
