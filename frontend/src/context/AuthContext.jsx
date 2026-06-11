/**
 * AuthContext.jsx — Global authentication state for AdaptiveScan
 *
 * Wraps the entire app. Provides:
 *   - user state (null = not authenticated)
 *   - login(email, password) → calls /api/auth/login
 *   - logout()
 *   - isAuthenticated boolean
 *
 * SECURITY:
 * - Custom token verification.
 * - Managed session handling.
 */
import React, { createContext, useContext, useState, useCallback, useEffect } from "react";

const API_BASE = "/api";
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // Local state for fallback local HS256 auth
  const [user, setUser] = useState(null);       // { email, role, name, organization_id, mfa_enabled, mfa_verified }
  const [loading, setLoading] = useState(true); // initial session check in progress
  const [error, setError] = useState(null);
  const [backendOffline, setBackendOffline] = useState(false);
  const [authReady, setAuthReady] = useState(false);

  // ── Check existing session on mount using /auth/me ────────────────────────
  // SECURITY: /auth/me extracts identity from the verified JWT cookie.
  const checkSession = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/me`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setUser({
          email: data.email,
          role: data.role,
          name: data.email?.split("@")[0] || "User",
          organization_id: data.organization_id,
          mfa_enabled: data.mfa_enabled,
          mfa_verified: data.mfa_verified,
        });
        setBackendOffline(false);
        setAuthReady(true);
      } else if (res.status === 401 || res.status === 403) {
        setUser(null);
        setBackendOffline(false);
        setAuthReady(true);
      } else {
        setBackendOffline(true);
        setAuthReady(false);
      }
    } catch {
      setBackendOffline(true);
      setAuthReady(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  // ── Listen for session expiry and MFA events from apiFetch in api.js ─────────────
  useEffect(() => {
    const handleExpiry = () => {
      setUser(null);
    };
    const handleMfaRequired = () => {
      checkSession();
    };
    window.addEventListener("adaptivescan:session-expired", handleExpiry);
    window.addEventListener("adaptivescan:mfa-required", handleMfaRequired);
    return () => {
      window.removeEventListener("adaptivescan:session-expired", handleExpiry);
      window.removeEventListener("adaptivescan:mfa-required", handleMfaRequired);
    };
  }, [checkSession]);

  // Ping backend periodically when offline
  useEffect(() => {
    if (!backendOffline) return;
    let delay = 3000;
    let timer;
    const runPing = async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/csrf`);
        if (res.ok) {
          setBackendOffline(false);
          checkSession();
        } else {
          delay = Math.min(delay * 1.5, 30000);
          timer = setTimeout(runPing, delay);
        }
      } catch {
        delay = Math.min(delay * 1.5, 30000);
        timer = setTimeout(runPing, delay);
      }
    };
    timer = setTimeout(runPing, delay);
    return () => clearTimeout(timer);
  }, [backendOffline, checkSession]);

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

      if (data.authenticated && data.tokens) {
        await checkSession();
        return { success: true, data, requiresMfa: false };
      } else if (data.requires_mfa) {
        return { success: true, data, requiresMfa: true, message: data.message };
      } else {
        const msg = data.reason || data.message || "Invalid credentials";
        setError(msg);
        return { success: false, message: msg, data };
      }
    } catch (err) {
      const msg = "Network error. Please check your connection.";
      setError(msg);
      return { success: false, message: msg, error: err.message };
    }
  }, [checkSession]);

  // ── Complete MFA ─────────────────────────────────────────────────────────
  const completeMfa = useCallback(async (email, code) => {
    setError(null);
    try {
      let res = await fetch(`${API_BASE}/auth/mfa/verify-login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, code }),
      });
      let data = await res.json();

      if (res.ok && data.authenticated) {
        await checkSession();
        return { success: true, data };
      }

      res = await fetch(`${API_BASE}/auth/otp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, code, purpose: "login_mfa" }),
      });
      data = await res.json();

      if (res.ok && data.verified && data.authenticated) {
        await checkSession();
        return { success: true, data };
      }

      const msg = data.reason || data.message || "Invalid or expired passcode. Please try again.";
      setError(msg);
      return { success: false, message: msg };
    } catch (err) {
      const msg = "Network error during MFA verification.";
      setError(msg);
      return { success: false, message: msg, error: err.message };
    }
  }, [checkSession]);

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
      // Ignore network errors
    }
    setUser(null);
    window.localStorage.removeItem("adaptiveScan.accessToken");
    window.localStorage.removeItem("adaptiveScan.refreshToken");
    window.localStorage.removeItem("adaptiveScan.pendingEmail");
  }, [user]);

  const value = {
    user,
    loading,
    error,
    backendOffline,
    authReady,
    isAuthenticated: !!user,
    login,
    completeMfa,
    register,
    logout,
    checkSession,
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

export async function authFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    credentials: "include",
  });
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent("adaptivescan:session-expired"));
    const err = new Error("Session expired");
    err.status = 401;
    throw err;
  }
  return res;
}
