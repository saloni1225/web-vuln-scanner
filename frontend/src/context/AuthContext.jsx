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
 * - The backend sets httpOnly cookies; the frontend never touches the raw JWT.
 * - Session check uses GET /api/auth/me which returns real identity from the verified JWT.
 *   (Previously used GET /api/reports and hardcoded user="admin/owner" — that was wrong.)
 * - All fetches use credentials: "include" to send the httpOnly session cookie.
 * - 401 responses dispatch "adaptivescan:session-expired" to force re-login.
 */
import React, { createContext, useContext, useState, useCallback, useEffect } from "react";

const API_BASE = "/api";
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);       // { email, role, name, organization_id }
  const [loading, setLoading] = useState(true); // initial session check in progress
  const [error, setError] = useState(null);

  // ── Listen for session expiry events from apiFetch in api.js ─────────────
  useEffect(() => {
    const handleExpiry = () => {
      setUser(null);
      // AuthProvider consumers will see isAuthenticated=false and redirect to /login
    };
    window.addEventListener("adaptivescan:session-expired", handleExpiry);
    return () => window.removeEventListener("adaptivescan:session-expired", handleExpiry);
  }, []);

  // ── Check existing session on mount using /auth/me ────────────────────────
  // SECURITY: /auth/me extracts identity from the verified JWT cookie.
  // It returns 401 if no valid cookie is present.
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/me`, { credentials: "include" });
        if (res.ok) {
          const data = await res.json();
          setUser({
            email: data.email,
            role: data.role,
            name: data.email?.split("@")[0] || "User",
            organization_id: data.organization_id,
          });
        }
        // 401 is expected when not logged in — just leave user as null
      } catch {
        // Network error — leave user as null, app will show login
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

      if (data.authenticated && data.tokens) {
        // No MFA — session is active, update user state from response
        setUser({
          email: data.user?.email || email,
          role: data.user?.role || "viewer",
          name: data.user?.first_name || email.split("@")[0],
        });
        return { success: true, data, requiresMfa: false };
      } else if (data.requires_mfa) {
        // MFA required — tokens NOT issued yet, user must complete OTP
        // Do NOT set user state until MFA is verified
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
  }, []);

  // ── Complete MFA ─────────────────────────────────────────────────────────
  // Called after user enters OTP code. On success, the backend issues cookies.
  const completeMfa = useCallback(async (email, code) => {
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/auth/otp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, code, purpose: "login_mfa" }),
      });
      const data = await res.json();
      if (data.verified && data.authenticated) {
        setUser({
          email: data.user?.email || email,
          role: data.user?.role || "viewer",
          name: data.user?.first_name || email.split("@")[0],
        });
        return { success: true, data };
      } else {
        const msg = "Invalid or expired OTP code. Please try again.";
        setError(msg);
        return { success: false, message: msg };
      }
    } catch (err) {
      const msg = "Network error during MFA verification.";
      setError(msg);
      return { success: false, message: msg, error: err.message };
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
      // Ignore network errors on logout — clear local state regardless
    }
    setUser(null);
    // Clear any localStorage tokens (defense-in-depth cleanup)
    window.localStorage.removeItem("adaptiveScan.accessToken");
    window.localStorage.removeItem("adaptiveScan.refreshToken");
    window.localStorage.removeItem("adaptiveScan.pendingEmail");
  }, [user]);

  const value = {
    user,
    loading,
    error,
    isAuthenticated: !!user,
    login,
    completeMfa,
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
 * Automatically includes credentials and throws on 401.
 */
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
