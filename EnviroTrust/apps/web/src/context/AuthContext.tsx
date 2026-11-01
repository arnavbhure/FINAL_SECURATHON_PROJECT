import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { User, Site } from '../types/index.js';
import { api } from '../api/client.js';

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  selectedSite: string;
  setSelectedSite: (site: string) => void;
  sites: Site[];
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    if (typeof localStorage !== 'undefined') {
      try {
        const cached = localStorage.getItem('envirotrust_user');
        return cached ? JSON.parse(cached) : null;
      } catch {
        return null;
      }
    }
    return null;
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [sites, setSites] = useState<Site[]>([]);
  const [selectedSite, setSelectedSite] = useState<string>('PLANT-001');

  // Handle unauthorized events (e.g. cookie expired or revoked session)
  const handleUnauthorized = useCallback(() => {
    setUser(null);
    setSites([]);
    try {
      localStorage.removeItem('envirotrust_user');
    } catch {}
  }, []);

  useEffect(() => {
    api.onUnauthorized(handleUnauthorized);
  }, [handleUnauthorized]);

  // Initial session recovery on application load
  const refreshUser = useCallback(async () => {
    try {
      const recovered = await api.refreshSession();
      if (recovered) {
        setUser(recovered);
        try {
          localStorage.setItem('envirotrust_user', JSON.stringify(recovered));
        } catch {}

        // Load sites available to this user (non-blocking for auth)
        try {
          const userSites = await api.getSites();
          setSites(userSites);

          if (recovered.role === 'PLATFORM_ADMIN') {
            if (userSites.length > 0 && userSites[0]) {
              setSelectedSite((prev) => prev || userSites[0]!.siteCode);
            }
          } else {
            if (recovered.sites.length > 0 && recovered.sites[0]) {
              setSelectedSite((prev) => prev || recovered.sites[0]!);
            }
          }
        } catch (siteErr) {
          console.warn('Failed to load user sites:', siteErr);
        }
      } else {
        setUser(null);
        try {
          localStorage.removeItem('envirotrust_user');
        } catch {}
      }
    } catch {
      setUser(null);
      try {
        localStorage.removeItem('envirotrust_user');
      } catch {}
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const res = await api.login(email, password);
      setUser(res.user);
      try {
        localStorage.setItem('envirotrust_user', JSON.stringify(res.user));
      } catch {}

      try {
        const userSites = await api.getSites();
        setSites(userSites);

        if (res.user.role === 'PLATFORM_ADMIN') {
          if (userSites.length > 0 && userSites[0]) {
            setSelectedSite(userSites[0].siteCode);
          }
        } else {
          if (res.user.sites.length > 0 && res.user.sites[0]) {
            setSelectedSite(res.user.sites[0]);
          }
        }
      } catch (siteErr) {
        console.warn('Failed to load sites after login:', siteErr);
      }
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await api.logout();
    } finally {
      setUser(null);
      setSites([]);
      try {
        localStorage.removeItem('envirotrust_user');
      } catch {}
      setLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        selectedSite,
        setSelectedSite,
        sites,
        login,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

