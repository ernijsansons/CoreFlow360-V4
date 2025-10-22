import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user';
  avatar?: string;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;

  // Actions
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  setUser: (user: User) => void;
}

/**
 * Authentication state with localStorage persistence
 * In production, replace with real JWT validation and refresh logic
 */
export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isAuthenticated: false,

      /**
       * Mock login - replace with real API call
       */
      login: async (email: string, password: string) => {
        // Simulate API call
        await new Promise((resolve) => setTimeout(resolve, 800));

        // Mock validation (accept any email/password for demo)
        if (email && password) {
          const mockUser: User = {
            id: '1',
            name: email.split('@')[0],
            email,
            role: 'admin',
            avatar: 'https://ui-avatars.com/api/?name=' + email.split('@')[0] + '&background=2563eb&color=fff',
          };

          const mockToken = 'mock-jwt-token-' + Date.now();

          set({
            user: mockUser,
            token: mockToken,
            isAuthenticated: true,
          });

          // Also store in localStorage for compatibility
          localStorage.setItem('token', mockToken);
        } else {
          throw new Error('Invalid credentials');
        }
      },

      /**
       * Logout and clear auth state
       */
      logout: () => {
        set({
          user: null,
          token: null,
          isAuthenticated: false,
        });
        localStorage.removeItem('token');
      },

      /**
       * Set user data (e.g., after profile update)
       */
      setUser: (user) => {
        set({ user });
      },
    }),
    {
      name: 'auth-storage', // localStorage key
      partialize: (state) => ({
        token: state.token,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);
