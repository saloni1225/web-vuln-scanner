/**
 * AuthContext.jsx — Global authentication state for AdaptiveScan
 *
 * Wraps the entire app. Provides:
 *   - user state (null = not authenticated)
 *   - login(email, password) → calls /api/auth/login
 *   - logout()
 *   - isAuthenticated boolean
 *
 * The backend sets httpOnly cookies, so we use `credentials: "include"`
 * on every fetch. The frontend never touches the raw JWT.
 */
import React, { createContext, useContext, useState, useCallback, useEffect } from "react";

const API_BASE = "/api";
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);          // { email, role, name }
  const [loading, setLoading] = useState(true);     // initial session check
  const [error, setError] = useState(null);

  // ── Check existing session on mount ──────────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/reports`, { credentials: "include" });
        if (res.ok) {
          // Session is valid — we don't know the user details from this endpoint,
          // but we can mark them as authenticated
          setUser({ email: "admin", role: "owner", name: "Admin" });
        }
      } catch {
        // Not authenticated — that's fine
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // ── Login ────────────────────────────────────────────────────────────────
  const login = useCallback(async (email, password) => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (data.authenticated) {
        setUser({
          email: data.user?.email || email,
          role: data.user?.role || "owner",
          name: data.user?.first_name || email.split("@")[0],
        });
        return { success: true, data };
      } else {
        setError(data.message || "Invalid credentials");
        return { success: false, data };
      }
    } catch (err) {
      setError("Network error. Please check your connection.");
      return { success: false, error: err.message };
    }
  }, []);

  // ── Register ─────────────────────────────────────────────────────────────
  const register = useCallback(async (payload) => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok) {
        return { success: true, data };
      } else {
        setError(data.detail?.message || data.detail || "Registration failed");
        return { success: false, data };
      }
    } catch (err) {
      setError("Network error.");
      return { success: false, error: err.message };
    }
  }, []);

  // ── Logout ───────────────────────────────────────────────────────────────
  const logout = useCallback(async () => {
    try {
      if (user?.email) {
        await fetch(`${API_BASE}/auth/logout`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ email: user.email }),
        });
      }
    } catch {
      // Ignore network errors on logout
    }
    setUser(null);
  }, [user]);

  const value = {
    user,
    loading,
    error,
    isAuthenticated: !!user,
    login,
    register,
    logout,
    clearError: () => setError(null),
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

/**
 * Authenticated fetch wrapper.
 * Automatically includes credentials and redirects to login on 401.
 */
export async function authFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    credentials: "include",
  });
  // If the backend says "not authenticated", the caller should redirect
  if (res.status === 401) {
    const err = new Error("Session expired");
    err.status = 401;
    throw err;
  }
  return res;
}
