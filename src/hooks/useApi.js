/**
 * API Hook pour le backend RGPD (version IMAP)
 * Copier dans src/hooks/useApi.js
 */
import { useState, useEffect, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

async function apiFetch(endpoint, options = {}) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  
  const data = await res.json();
  
  if (!res.ok) {
    throw new Error(data.error || 'Erreur API');
  }
  
  return data;
}

export function useApi() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [emails, setEmails] = useState([]);
  const [error, setError] = useState(null);

  // Check auth on mount
  useEffect(() => {
    apiFetch('/auth/status')
      .then(data => {
        if (data.authenticated) {
          setUser(data.user);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  // Refresh emails
  const refreshEmails = useCallback(async () => {
    if (!user) return;
    try {
      const data = await apiFetch('/emails');
      setEmails(data);
    } catch (e) {
      setError(e.message);
    }
  }, [user]);

  useEffect(() => {
    if (user) {
      refreshEmails();
    }
  }, [user, refreshEmails]);

  return {
    user,
    loading,
    emails,
    error,
    setError,
    
    // Auth
    login: async (email, appPassword) => {
      setError(null);
      try {
        await apiFetch('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email, app_password: appPassword }),
        });
        const status = await apiFetch('/auth/status');
        if (status.authenticated) {
          setUser(status.user);
        }
        return { success: true };
      } catch (e) {
        setError(e.message);
        return { success: false, error: e.message };
      }
    },
    
    logout: async () => {
      await apiFetch('/auth/logout', { method: 'POST' });
      setUser(null);
      setEmails([]);
    },
    
    // Profile
    updateProfile: async (data) => {
      await apiFetch('/profile', {
        method: 'PUT',
        body: JSON.stringify(data),
      });
      setUser(prev => ({ ...prev, ...data }));
    },
    
    // Emails
    scanEmails: async () => {
      setError(null);
      try {
        const result = await apiFetch('/emails/scan', { method: 'POST' });
        await refreshEmails();
        return result;
      } catch (e) {
        setError(e.message);
        throw e;
      }
    },
    
    deleteEmail: async (id) => {
      await apiFetch(`/emails/${id}`, { method: 'DELETE' });
      setEmails(prev => prev.filter(e => e.id !== id));
    },
    
    blockEmail: async (id) => {
      await apiFetch(`/emails/${id}/block`, { method: 'POST' });
      setEmails(prev => prev.filter(e => e.id !== id));
    },
    
    toggleProtection: async (id) => {
      const result = await apiFetch(`/emails/${id}/protect`, { method: 'POST' });
      setEmails(prev => prev.map(e => 
        e.id === id ? { ...e, isProtected: result.isProtected } : e
      ));
    },
    
    bulkDelete: async () => {
      const result = await apiFetch('/emails/bulk-delete', { method: 'POST' });
      await refreshEmails();
      return result;
    },
    
    // RGPD
    findDpo: async (domain) => {
      return apiFetch('/rgpd/find-dpo', {
        method: 'POST',
        body: JSON.stringify({ domain }),
      });
    },
    
    sendRgpdRequest: async (emailId, dpoEmail) => {
      const result = await apiFetch('/rgpd/send', {
        method: 'POST',
        body: JSON.stringify({ email_id: emailId, dpo_email: dpoEmail }),
      });
      await refreshEmails();
      return result;
    },
    
    getRgpdCases: async () => {
      return apiFetch('/rgpd/cases');
    },
    
    escalateToCnil: async (caseId) => {
      return apiFetch(`/rgpd/cases/${caseId}/escalate`, { method: 'POST' });
    },
    
    getStats: async () => {
      return apiFetch('/stats');
    },
    
    refreshEmails,
  };
}

export default useApi;
