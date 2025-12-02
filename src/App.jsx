import React, { useState, useEffect } from 'react';
import { 
  Play, Check, Trash2, Shield, AlertTriangle, Loader2, 
  LayoutDashboard, Inbox, Settings, LogOut, Lock, Unlock, 
  Ban, Send, Clock, ChevronRight, X, List, UserCheck, UserX, FileText,
  RefreshCw, Search, Mail, Zap, ChevronDown, ChevronUp, Sparkles 
} from 'lucide-react';

const LOADER_CSS = `
.loader-toast {
  position: fixed;
  bottom: 32px;
  right: 32px;
  width: auto;
  max-width: 400px;
  background: rgba(20, 20, 20, 0.95);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 12px;
  padding: 16px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
  z-index: 9999;
  animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
  transition: all 0.2s ease;
}
.minimal-spinner {
  width: 24px;
  height: 24px;
  border: 2px solid rgba(255, 255, 255, 0.1);
  border-radius: 50%;
  border-top-color: #6366f1;
  border-right-color: #6366f1;
  animation: spin 1s linear infinite;
  flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes slideIn { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
.loader-info { display: flex; flex-direction: column; text-align: left; }
.loader-info h2 { color: white; font-family: -apple-system, sans-serif; font-size: 14px; font-weight: 600; margin: 0; }
.loader-info p { color: #9ca3af; font-family: monospace; font-size: 11px; margin: 4px 0 0 0; }
`;

const SimpleLoader = ({ progress, onStop }) => (
  <div className="loader-toast group">
    <div className="flex items-center gap-4">
      <div className="relative"><div className="minimal-spinner text-indigo-500"></div></div>
      <div className="loader-info"><h2>Scanning ({progress?.percent || 0}%)</h2><p>{progress?.action || "Processing..."}</p></div>
    </div>
    <button onClick={onStop} className="ml-4 p-2 rounded-full bg-red-50 text-red-500 hover:bg-red-500 hover:text-white transition-all opacity-0 group-hover:opacity-100"><X className="w-4 h-4"/></button>
  </div>
);

const getDomainFromEmail = (email) => email.split('@')[1] || '';
const getFaviconUrl = (email) => `https://www.google.com/s2/favicons?domain=${getDomainFromEmail(email)}&sz=32`;

const MessageBubble = ({ msg, isMe }) => {
    const [isExpanded, setIsExpanded] = useState(!msg.summary);
    return (
        <div className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-lg rounded-2xl p-6 shadow-sm border transition-all ${isMe ? 'bg-indigo-600 text-white shadow-indigo-200 border-indigo-500' : 'bg-white border-gray-100 text-gray-800'}`}>
                <div className={`flex justify-between items-center mb-3 text-xs ${isMe?'text-indigo-200':'text-gray-400'}`}>
                    <span className="font-bold uppercase tracking-wide">{msg.senderName || (isMe ? "Me" : "Company")}</span>
                    <span>{msg.date}</span>
                </div>
                <h4 className="font-bold text-sm mb-2">{msg.subject}</h4>
                {msg.summary && !isExpanded ? (
                    <div className="animate-in fade-in duration-300">
                        <div className="flex gap-2 items-start mb-2"><Sparkles className="w-4 h-4 text-purple-500 mt-0.5 flex-shrink-0"/><p className="text-sm italic text-gray-600 leading-relaxed font-medium bg-purple-50 px-3 py-2 rounded-lg border border-purple-100 w-full">{msg.summary}</p></div>
                        <button onClick={() => setIsExpanded(true)} className="text-xs font-bold text-indigo-500 flex items-center gap-1 hover:text-indigo-700 transition">Read full email <ChevronDown className="w-3 h-3"/></button>
                    </div>
                ) : (
                    <div className="animate-in fade-in duration-300">
                         {msg.summary && <div className="mb-3 pb-3 border-b border-gray-100/50"><span className="text-[10px] font-bold uppercase tracking-wider text-purple-400 flex items-center gap-1 mb-1"><Sparkles className="w-3 h-3"/> AI Summary</span><p className="text-xs italic opacity-80">{msg.summary}</p></div>}
                         <p className="text-sm whitespace-pre-wrap leading-relaxed opacity-90">{msg.body}</p>
                         {msg.summary && <button onClick={() => setIsExpanded(false)} className="mt-3 text-xs font-bold opacity-60 flex items-center gap-1 hover:opacity-100 transition">Show less <ChevronUp className="w-3 h-3"/></button>}
                    </div>
                )}
            </div>
        </div>
    );
};

const ProtectionModal = ({ email, onClose, onProtectSingle, onProtectSender }) => (
    <div className="fixed inset-0 bg-black/20 backdrop-blur-sm z-[60] flex items-center justify-center p-4 animate-in fade-in duration-200" onClick={onClose}>
        <div className="bg-white/95 backdrop-blur-xl rounded-3xl w-full max-w-sm shadow-2xl p-6 border border-white/50" onClick={(e) => e.stopPropagation()}>
            <div className="text-center mb-6"><div className="w-12 h-12 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-sm"><Lock className="w-6 h-6"/></div><h3 className="text-lg font-bold text-gray-900">Protect this item?</h3></div>
            <div className="space-y-3">
                <button onClick={() => onProtectSingle(email)} className="w-full flex items-center gap-3 p-4 bg-white border border-gray-100 rounded-xl hover:shadow-md transition-all text-left"><div className="bg-gray-50 p-2 rounded-lg"><FileText className="w-5 h-5 text-gray-600"/></div><div><div className="font-bold text-gray-900 text-sm">Only this email</div></div></button>
                <button onClick={() => onProtectSender(email)} className="w-full flex items-center gap-3 p-4 bg-green-50/50 border border-green-100 rounded-xl hover:shadow-md transition-all text-left"><div className="bg-green-100 p-2 rounded-lg text-green-700"><UserCheck className="w-5 h-5"/></div><div><div className="font-bold text-green-900 text-sm">Trusted Sender</div></div></button>
            </div>
            <button onClick={onClose} className="w-full mt-6 text-gray-400 text-xs font-bold hover:text-gray-600 uppercase tracking-wider">Cancel</button>
        </div>
    </div>
);

const UnprotectModal = ({ email, onClose, onUnprotectSingle, onUnprotectSender }) => (
    <div className="fixed inset-0 bg-black/20 backdrop-blur-sm z-[60] flex items-center justify-center p-4 animate-in fade-in duration-200" onClick={onClose}>
        <div className="bg-white/95 backdrop-blur-xl rounded-3xl w-full max-w-sm shadow-2xl p-6 border border-white/50" onClick={(e) => e.stopPropagation()}>
            <div className="text-center mb-6"><div className="w-12 h-12 bg-orange-50 text-orange-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-sm"><Unlock className="w-6 h-6"/></div><h3 className="text-lg font-bold text-gray-900">Remove protection?</h3></div>
            <div className="space-y-3">
                <button onClick={() => onUnprotectSingle(email)} className="w-full flex items-center gap-3 p-4 bg-white border border-gray-100 rounded-xl hover:shadow-md transition-all text-left"><div className="bg-gray-50 p-2 rounded-lg"><FileText className="w-5 h-5 text-gray-600"/></div><div><div className="font-bold text-gray-900 text-sm">Unlock email</div></div></button>
                <button onClick={() => onUnprotectSender(email)} className="w-full flex items-center gap-3 p-4 bg-red-50/50 border border-red-100 rounded-xl hover:shadow-md transition-all text-left"><div className="bg-red-100 p-2 rounded-lg text-red-700"><UserX className="w-5 h-5"/></div><div><div className="font-bold text-red-900 text-sm">Remove from Whitelist</div></div></button>
            </div>
            <button onClick={onClose} className="w-full mt-6 text-gray-400 text-xs font-bold hover:text-gray-600 uppercase tracking-wider">Cancel</button>
        </div>
    </div>
);

const RgpdModal = ({ email, onClose, onConfirmSuccess, user }) => {
  const [loading, setLoading] = useState(false);
  const [searchingWeb, setSearchingWeb] = useState(true); 
  const [dpoEmail, setDpoEmail] = useState("");
  const [emailSource, setEmailSource] = useState("init"); 
  const isProfileComplete = user.full_name && user.address && user.city;

  useEffect(() => {
    const startAutoScan = async () => {
        const domain = getDomainFromEmail(email.sender_email) || "unknown-domain.com";
        setDpoEmail(`dpo@${domain}`); 
        try {
            const cleanName = email.sender.split('<')[0].trim();
            const res = await fetch('/api/rgpd/search-contact', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ company_name: cleanName, domain: domain }) });
            const data = await res.json();
            if (data.success && data.email) { setDpoEmail(data.email); setEmailSource(data.source.includes('web') ? 'web' : 'default'); }
        } catch (e) {} finally { setSearchingWeb(false); }
    };
    startAutoScan();
  }, [email]);

  const handleSend = async () => { 
      if (!isProfileComplete) return;
      setLoading(true); 
      const response = await fetch('/api/rgpd/send', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ email_id: email.id, dpo_email: dpoEmail }) });
      if(response.ok) { onConfirmSuccess(); onClose(); } else { alert('Failed to send request'); }
      setLoading(false); 
  };

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in duration-200" onClick={onClose}>
      <div className="bg-white rounded-2xl w-full max-w-md shadow-2xl overflow-hidden border border-gray-100" onClick={(e) => e.stopPropagation()}>
        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100 flex justify-between items-center">
          <div className="flex items-center gap-2 text-gray-900 font-bold"><Shield className="w-5 h-5 text-indigo-600"/> Action Required</div>
          <button onClick={onClose}><X className="w-5 h-5 text-gray-400"/></button>
        </div>
        <div className="p-6 space-y-6">
          <div className="text-center"><h2 className="text-xl font-bold text-gray-900">Right to be Forgotten</h2><p className="text-sm text-gray-500">Exercise your GDPR rights with <strong>{email.sender}</strong>.</p></div>
          {!isProfileComplete && <div className="bg-red-50 border border-red-200 text-red-800 p-3 rounded-xl flex items-center gap-3 text-sm font-medium"><AlertTriangle className="w-5 h-5 flex-shrink-0"/><span>Profile Incomplete.</span></div>}
          <div className="bg-white border border-gray-200 rounded-xl p-4 shadow-sm relative overflow-hidden transition-all duration-300">
            <div className="flex justify-between items-center mb-2">
                <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">Target DPO Email</span>
                {searchingWeb ? <span className="text-[10px] bg-indigo-50 text-indigo-600 px-2 py-1 rounded-full font-bold flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin"/> Scanning...</span> : <span className={`text-[10px] px-2 py-1 rounded-full font-bold flex items-center gap-1 ${emailSource.includes('web')?'bg-green-50 text-green-700':'bg-gray-100 text-gray-500'}`}>{emailSource.includes('web') ? 'Found on Web' : 'Default Guess'}</span>}
            </div>
            <div className="flex items-center gap-2 p-3 rounded-lg border bg-gray-50 border-gray-200"><Mail className="w-4 h-4 text-gray-400"/><input value={dpoEmail} onChange={(e) => setDpoEmail(e.target.value)} className="bg-transparent border-none w-full text-sm font-mono font-medium text-gray-700 focus:outline-none"/></div>
          </div>
          <button onClick={handleSend} disabled={loading || searchingWeb || !isProfileComplete} className="btn-primary w-full py-3 rounded-xl font-bold flex items-center justify-center gap-2 shadow-lg shadow-indigo-200 transition-all hover:scale-[1.02] disabled:opacity-50">{loading ? <Loader2 className="w-5 h-5 animate-spin"/> : <Send className="w-4 h-4"/>} Send Request</button>
        </div>
      </div>
    </div>
  );
};

const AddResponseForm = ({ caseId, onResponseAdded, onClose }) => {
    const [subject, setSubject] = useState("");
    const [body, setBody] = useState("");
    const [loading, setLoading] = useState(false);
    const handleAdd = async () => {
        if (!subject || !body) return;
        setLoading(true);
        const response = await fetch(`/api/rgpd/inbox`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ case_id: caseId, subject, body }) });
        if (response.ok) { onResponseAdded(); onClose(); }
        setLoading(false);
    };
    return (
        <div className="p-4 bg-white border border-gray-200 rounded-xl mt-4">
            <h4 className="font-bold text-gray-800 mb-3">Add Manual Response</h4>
            <input type="text" placeholder="Subject" value={subject} onChange={(e) => setSubject(e.target.value)} className="w-full p-2 mb-3 border border-gray-300 rounded-lg text-sm"/>
            <textarea placeholder="Body" value={body} onChange={(e) => setBody(e.target.value)} className="w-full p-2 mb-3 border border-gray-300 rounded-lg text-sm h-24 resize-none"/>
            <div className="flex justify-end gap-2"><button onClick={onClose} className="text-gray-500 text-sm">Cancel</button><button onClick={handleAdd} disabled={loading} className="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm font-bold">{loading ? <Loader2 className="w-4 h-4 animate-spin"/> : "Save"}</button></div>
        </div>
    );
};

const CaseDetailModal = ({ dossier, onClose, onUpdateCase }) => {
  if (!dossier) return null;
  const [showAddResponse, setShowAddResponse] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const sortedMessages = [...dossier.messages].sort((a, b) => new Date(a.date) - new Date(b.date));
  const lastMsg = sortedMessages.length > 0 ? sortedMessages[sortedMessages.length - 1] : null;
  const showAiButton = lastMsg && lastMsg.from === 'them' && dossier.status !== 'completed';

  const handleConfirmDeletion = async () => {
      setConfirming(true);
      try {
          const response = await fetch('/api/rgpd/confirm-reply', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ case_id: dossier.id }) });
          if (response.ok) { await onUpdateCase(); } else { alert("Failed to send confirmation"); }
      } catch (e) { alert("Error"); } finally { setConfirming(false); }
  };

  return (
    <div className="fixed inset-0 bg-white/50 backdrop-blur-sm z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-4xl bg-white h-full shadow-2xl animate-in slide-in-from-right duration-300 flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="px-8 py-5 border-b border-gray-100 flex justify-between items-center bg-white/80 backdrop-blur-md sticky top-0 z-10">
          <div className="flex items-center gap-4"><button onClick={onClose} className="p-2 hover:bg-gray-100 rounded-full transition"><X className="w-5 h-5 text-gray-500"/></button><h2 className="font-bold text-xl text-gray-900">GDPR Case File</h2></div>
          <div className="flex gap-2"><span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide border ${dossier.status === 'completed' ? 'bg-green-100 text-green-700 border-green-200' : 'bg-gray-100 text-gray-500 border-gray-200'}`}>{dossier.status.replace('_', ' ')}</span></div>
        </div>
        <div className="flex flex-1 overflow-hidden">
          <div className="flex-1 bg-gray-50/50 p-8 overflow-y-auto">
            <div className="max-w-2xl mx-auto space-y-8">
              <div className="text-center">
                <img src={getFaviconUrl(dossier.dpo_email)} alt={dossier.company_name.charAt(0)} className="w-16 h-16 rounded-full shadow-lg mx-auto mb-4 border border-gray-200 object-contain" onError={(e) => { e.target.onerror = null; e.target.src = "https://placehold.co/64x64/E0E7FF/4F46E5?text=" + dossier.company_name.charAt(0).toUpperCase(); }} />
                <h1 className="text-2xl font-bold text-gray-900">{dossier.company_name}</h1>
                <p className="text-gray-500 font-mono text-sm">{dossier.dpo_email}</p>
              </div>
              <div className="space-y-6 pb-10">
                {sortedMessages.map((msg, i) => (
                   <MessageBubble key={i} msg={msg} isMe={msg.from === 'me'} />
                ))}
              </div>
            </div>
          </div>
          <div className="w-80 bg-white border-l border-gray-100 p-8 flex flex-col shadow-[0_0_40px_rgba(0,0,0,0.03)] z-20">
            {showAiButton && (
                <div className="mb-6 p-1 bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500 rounded-2xl shadow-lg shadow-indigo-200">
                    <div className="bg-white rounded-xl p-5 text-center">
                        <div className="w-10 h-10 bg-indigo-50 text-indigo-600 rounded-full flex items-center justify-center mx-auto mb-3"><Zap className="w-5 h-5 fill-current"/></div>
                        <h3 className="font-bold text-gray-900 mb-1">New Reply Detected</h3>
                        <p className="text-xs text-gray-500 mb-4">They replied. Do you want the AI to confirm the deletion request?</p>
                        <button onClick={handleConfirmDeletion} disabled={confirming} className="w-full bg-indigo-600 text-white py-3 rounded-lg text-sm font-bold hover:bg-indigo-700 disabled:opacity-50 flex items-center justify-center gap-2 transition-all hover:scale-[1.02]">{confirming ? <Loader2 className="w-4 h-4 animate-spin"/> : <RefreshCw className="w-4 h-4"/>} Reply with AI</button>
                    </div>
                </div>
            )}
            <div className="mb-6"><button onClick={() => setShowAddResponse(true)} className="w-full py-3 rounded-xl font-bold flex items-center justify-center gap-2 border border-gray-200 text-gray-600 hover:bg-gray-50 transition"><Mail className="w-4 h-4"/> Log Manual Response</button>{showAddResponse && <AddResponseForm caseId={dossier.id} onResponseAdded={onUpdateCase} onClose={() => setShowAddResponse(false)}/> }</div>
            <div className="mt-auto pt-6 border-t border-gray-50">
              <h3 className="text-xs font-bold text-gray-400 uppercase mb-4 tracking-wider">Status</h3>
              <div className="text-sm text-gray-600 leading-relaxed">{dossier.status === 'completed' ? "Deletion confirmed. Case closed." : "Waiting for procedure completion. Standard timeframe is 30 days."}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default function DeletrrApp() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userProfile, setUserProfile] = useState({});
  const [emails, setEmails] = useState([]);
  const [cases, setCases] = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard'); 
  const [scanStatus, setScanStatus] = useState('idle'); 
  const [progressData, setProgressData] = useState(null);
  const [filterMode, setFilterMode] = useState('ALL'); 
  const [visibleCount, setVisibleCount] = useState(50);
  const [processingIds, setProcessingIds] = useState({});
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [isLoadingAuth, setIsLoadingAuth] = useState(true);
  const [rgpdModalTarget, setRgpdModalTarget] = useState(null);
  const [selectedCase, setSelectedCase] = useState(null);
  const [protectionModalTarget, setProtectionModalTarget] = useState(null);
  const [unprotectModalTarget, setUnprotectModalTarget] = useState(null);

  useEffect(() => { checkAuth(); }, []);

  useEffect(() => {
    let interval;
    if (scanStatus === 'scanning') {
        interval = setInterval(async () => {
            try {
                const res = await fetch('/api/emails/scan/progress');
                const data = await res.json();
                setProgressData(data);
                if (data.status === 'complete' || data.status === 'stopped') { setScanStatus('idle'); clearInterval(interval); fetchData(); }
            } catch (e) {}
        }, 1000);
    }
    return () => clearInterval(interval);
  }, [scanStatus]);

  const checkAuth = async () => {
    try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        if (data.authenticated) { setIsAuthenticated(true); setUserProfile(data.user); fetchData(); } else { setIsAuthenticated(false); }
    } catch (err) { setIsAuthenticated(false); } finally { setIsLoadingAuth(false); }
  };

  const fetchData = async () => {
      const res = await fetch('/api/emails');
      setEmails(await res.json());
      const resCases = await fetch('/api/rgpd/cases');
      const updatedCases = await resCases.json();
      setCases(updatedCases);
      if (selectedCase) { const updatedCase = updatedCases.find(c => c.id === selectedCase.id); if (updatedCase) setSelectedCase(updatedCase); }
  };

  const updateSelectedCase = async () => {
       const resCases = await fetch('/api/rgpd/cases');
       const updatedCases = await resCases.json();
       setCases(updatedCases);
       if (selectedCase) { const updatedCase = updatedCases.find(c => c.id === selectedCase.id); if (updatedCase) setSelectedCase(updatedCase); }
  }

  const startScan = async () => { setScanStatus('scanning'); setVisibleCount(50); await fetch('/api/emails/scan', { method: 'POST' }); };
  const stopScan = async () => { await fetch('/api/emails/scan/stop', { method: 'POST' }); };
  const handleLockClick = (e, item) => { e.stopPropagation(); item.isProtected ? setUnprotectModalTarget(item) : setProtectionModalTarget(item); };
  
  const handleProtectSingle = async (item) => { setProtectionModalTarget(null); setEmails(prev => prev.map(em => em.id === item.id ? {...em, isProtected: true} : em)); await fetch(`/api/emails/${item.id}/protect`, { method: 'POST' }); };
  const handleProtectSender = async (item) => { setProtectionModalTarget(null); await fetch('/api/whitelist', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ email: item.sender_email, name: item.sender }) }); fetchData(); };
  const handleUnprotectSingle = async (item) => { setUnprotectModalTarget(null); setEmails(prev => prev.map(em => em.id === item.id ? {...em, isProtected: false} : em)); await fetch(`/api/emails/${item.id}/protect`, { method: 'POST' }); };
  const handleUnprotectSender = async (item) => { setUnprotectModalTarget(null); await fetch('/api/whitelist/remove-sender', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ email: item.sender_email }) }); fetchData(); };
  const handleDeleteOne = async (e, id) => { e.stopPropagation(); setProcessingIds(prev => ({ ...prev, [id]: true })); try { setEmails(prev => prev.filter(email => email.id !== id)); } catch (err) {} finally { setProcessingIds(prev => ({ ...prev, [id]: false })); } };
  const handleBulkClean = async () => { if(!confirm("Delete all?")) return; setBulkDeleting(true); await fetch('/api/emails/bulk-delete', { method: 'POST' }); setBulkDeleting(false); fetchData(); };
  const handleUpdateProfile = async () => { await fetch('/api/profile', { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(userProfile) }); alert("Profile Saved"); };
  const handleResetDB = async () => { if(!confirm("Reset DB?")) return; await fetch('/api/reset', { method: 'POST' }); setEmails([]); setScanStatus('idle'); };
  
  const getActionUI = (action) => {
    switch (action) {
      case 'DELETE': return { label: 'Delete', color: 'text-red-600', bg: 'bg-red-50 border-red-200' };
      case 'RGPD_UNSUB': return { label: 'GDPR', color: 'text-purple-600', bg: 'bg-purple-50 border-purple-200' };
      case 'KEEP': return { label: 'Keep', color: 'text-green-600', bg: 'bg-green-50 border-green-200' };
      default: return { label: action || 'Unknown', color: 'text-gray-600', bg: 'bg-gray-50 border-gray-200' };
    }
  };

  if (isLoadingAuth) return <div className="h-screen flex items-center justify-center"><div className="light-bg"><div className="orb orb-1"></div><div className="orb orb-2"></div></div><Loader2 className="w-10 h-10 animate-spin text-indigo-600"/></div>;
  if (!isAuthenticated) return <LoginScreen onLogin={async (email, pwd) => { await fetch('/api/auth/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ email, app_password: pwd }) }); checkAuth(); }} />;

  const allDetected = emails.filter(e => e.status === 'detected');
  const activeCasesSenders = new Set(cases.map(c => c.company_email));
  const listForDashboard = allDetected.filter(e => { if (e.action === 'RGPD_UNSUB' && activeCasesSenders.has(e.sender_email)) return false; return true; });
  const filteredList = filterMode === 'ALL' ? listForDashboard : listForDashboard.filter(e => e.action === filterMode);
  const displayedList = filteredList.slice(0, visibleCount);
  const itemsToDelete = listForDashboard.filter(e => e.action === 'DELETE').length;
  const counts = { ALL: listForDashboard.length, DELETE: itemsToDelete, RGPD_UNSUB: listForDashboard.filter(e=>e.action==='RGPD_UNSUB').length, KEEP: listForDashboard.filter(e=>e.action==='KEEP').length };

  return (
    <div className="min-h-screen font-sans flex text-sm">
      <style dangerouslySetInnerHTML={{ __html: LOADER_CSS }} />
      <div className="light-bg"><div className="orb orb-1"></div><div className="orb orb-2"></div><div className="orb orb-3"></div></div>
      {scanStatus === 'scanning' && <SimpleLoader progress={progressData} onStop={stopScan} />}
      {rgpdModalTarget && <RgpdModal email={rgpdModalTarget} user={userProfile} onClose={() => setRgpdModalTarget(null)} onConfirmSuccess={fetchData} />}
      {selectedCase && <CaseDetailModal dossier={selectedCase} onClose={() => setSelectedCase(null)} onUpdateCase={updateSelectedCase} />}
      {protectionModalTarget && <ProtectionModal email={protectionModalTarget} onClose={() => setProtectionModalTarget(null)} onProtectSingle={handleProtectSingle} onProtectSender={handleProtectSender} />}
      {unprotectModalTarget && <UnprotectModal email={unprotectModalTarget} onClose={() => setUnprotectModalTarget(null)} onUnprotectSingle={handleUnprotectSingle} onUnprotectSender={handleUnprotectSender} />}

      <div className="w-64 glass-panel border-r-0 rounded-r-3xl m-4 flex flex-col p-4 shrink-0 z-10 h-[calc(100vh-2rem)]">
         <div className="flex items-center gap-3 px-3 py-4 mb-6"><div className="w-8 h-8 flex items-center justify-center text-indigo-600 bg-white rounded-lg shadow-sm"><Shield className="w-6 h-6"/></div><span className="font-bold text-lg tracking-tight text-gray-800">DELETRR</span></div>
         <div className="space-y-1 flex-1">
             <NavButton active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} icon={LayoutDashboard} label="Dashboard" count={allDetected.length || null} />
             <NavButton active={activeTab === 'tracking'} onClick={() => setActiveTab('tracking')} icon={Inbox} label="Tracking" count={cases.length || null} />
             <NavButton active={activeTab === 'settings'} onClick={() => setActiveTab('settings')} icon={Settings} label="Settings" />
         </div>
         <div className="mt-auto pt-6 border-t border-gray-100"><div className="px-3 py-3 text-xs text-gray-500 flex items-center gap-2 mb-2 bg-white/50 rounded-lg border border-white truncate font-medium">{userProfile.email}</div><button onClick={async() => {await fetch('/api/auth/logout', {method:'POST'}); setIsAuthenticated(false); setEmails([]);}} className="flex items-center gap-2 text-gray-400 hover:text-red-500 px-3 py-2 text-xs w-full font-bold transition"><LogOut className="w-3 h-3"/> Logout</button></div>
      </div>

      <div className="flex-1 flex flex-col h-screen overflow-hidden relative z-0">
        {activeTab === 'dashboard' && (
            <div className="flex-1 overflow-y-auto p-10 animate-in fade-in slide-in-from-left duration-300">
                <header className="mb-8 flex justify-between items-start">
                    <div><h1 className="text-3xl font-extrabold text-gray-800 mb-1">Dashboard</h1><p className="text-gray-500">Manage your digital hygiene.</p></div>
                    <div className="flex items-center gap-3">
                         <button onClick={startScan} className="bg-white hover:bg-gray-50 text-gray-700 border border-gray-200 px-4 py-3 rounded-xl font-bold text-sm shadow-sm transition-all flex items-center gap-2"><RefreshCw className={`w-4 h-4 ${scanStatus === 'scanning' ? 'animate-spin' : ''}`}/><span>{scanStatus === 'scanning' ? 'Scanning...' : 'Scan Inbox'}</span></button>
                         {itemsToDelete > 0 && <button onClick={handleBulkClean} disabled={bulkDeleting} className="bg-red-500 hover:bg-red-600 text-white px-6 py-3 rounded-xl font-bold text-sm shadow-lg shadow-red-200 transition-all disabled:opacity-50 whitespace-nowrap flex items-center gap-2">{bulkDeleting ? <Loader2 className="animate-spin w-4 h-4"/> : <Trash2 className="w-4 h-4"/>} <span>Purge ({itemsToDelete})</span></button>}
                    </div>
                </header>
                {scanStatus === 'idle' && allDetected.length === 0 && <div className="glass-panel p-16 rounded-3xl text-center border-dashed border-2 border-gray-300"><div className="w-20 h-20 bg-white rounded-full flex items-center justify-center mx-auto mb-6 shadow-xl text-indigo-500"><Inbox className="w-10 h-10"/></div><h3 className="text-xl font-bold text-gray-800 mb-2">Ready to clean?</h3><button onClick={startScan} className="mt-6 btn-primary px-8 py-3 rounded-full font-bold shadow-xl flex items-center gap-2 mx-auto"><Play className="w-5 h-5"/> Start Scan</button></div>}
                {(scanStatus !== 'idle' || allDetected.length > 0) && (
                    <div className="animate-in fade-in duration-500">
                        <FilterTabs current={filterMode} onChange={(v) => { setFilterMode(v); setVisibleCount(50); }} counts={counts} />
                        <div className="glass-panel rounded-2xl overflow-hidden border border-white/60 shadow-xl">
                            <div className="grid-header bg-gray-50/80 border-b border-gray-100/50"><div></div><div>Sender</div><div>Subject</div><div>Status</div><div className="text-center">Security</div><div className="text-right">Action</div></div>
                            {displayedList.map((item) => {
                                const ui = getActionUI(item.action);
                                const hasActiveGdprCase = cases.some(c => c.company_email === item.sender_email);
                                return (
                                    <div key={item.id} className="grid-row group hover:bg-white/60 transition-colors">
                                        <div className="w-9 h-9 rounded-xl flex items-center justify-center shadow-sm border border-gray-100 p-1"><img src={getFaviconUrl(item.sender_email)} alt={item.sender.charAt(0)} className="w-full h-full object-contain rounded-full" onError={(e) => { e.target.onerror = null; e.target.src = "https://placehold.co/32x32/E0E7FF/4F46E5?text=" + item.sender.charAt(0).toUpperCase(); }} /></div>
                                        <div className="truncate font-semibold text-gray-800">{item.sender}</div>
                                        <div className="text-xs text-gray-500 truncate font-medium">{item.subject}</div>
                                        <div className="flex items-center"><span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border uppercase tracking-wider ${ui.color} ${ui.bg}`}>{ui.label}</span></div>
                                        <div className="flex justify-center"><button onClick={(e) => handleLockClick(e, item)} className={`p-2 rounded-lg transition ${item.isProtected ? 'text-indigo-600 bg-indigo-50 border border-indigo-100' : 'text-gray-300 hover:text-gray-500 hover:bg-gray-100'}`}>{item.isProtected ? <Lock className="w-3.5 h-3.5"/> : <Unlock className="w-3.5 h-3.5"/>}</button></div>
                                        <div className="text-right">
                                            {!item.isProtected && item.action === 'DELETE' && <button onClick={(e) => handleDeleteOne(e, item.id)} disabled={processingIds[item.id]} className="text-red-500 hover:bg-red-50 hover:text-red-700 px-3 py-1.5 rounded-lg text-xs font-bold transition">{processingIds[item.id] ? <Loader2 className="w-3 h-3 animate-spin"/> : "Delete"}</button>}
                                            {!item.isProtected && item.action === 'RGPD_UNSUB' && (hasActiveGdprCase ? <span className="text-purple-500 px-3 py-1.5 rounded-lg text-xs font-medium flex items-center justify-end gap-1"><Zap className="w-3 h-3"/> Sent</span> : <button onClick={(e)=>{e.stopPropagation(); setRgpdModalTarget(item)}} className="bg-indigo-600 text-white px-4 py-1.5 rounded-lg text-xs font-bold hover:bg-indigo-700 shadow-sm transition">Manage</button>)}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                        {displayedList.length < filteredList.length && <button onClick={() => setVisibleCount(c => c + 50)} className="w-full mt-6 py-4 glass-panel text-gray-500 font-bold rounded-xl hover:bg-white transition">Load more emails</button>}
                    </div>
                )}
            </div>
        )}
        
        {/* TRACKING TAB */}
        {activeTab === 'tracking' && (
            <div className="flex-1 overflow-y-auto p-10 animate-in fade-in slide-in-from-left duration-300">
                <header className="mb-8"><h1 className="text-3xl font-extrabold text-gray-800 mb-2">GDPR Tracking</h1><p className="text-gray-500">History of your deletion requests.</p></header>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {cases.map(c => {
                        const lastMsg = c.messages && c.messages.length > 0 ? c.messages[c.messages.length - 1] : null;
                        const hasNewReply = lastMsg && lastMsg.from === 'them';
                        return (
                            <div key={c.id} onClick={()=>setSelectedCase(c)} className={`glass-panel p-6 rounded-2xl hover:shadow-lg transition cursor-pointer group border ${hasNewReply ? 'border-indigo-300 shadow-indigo-100' : 'border-white/60'}`}>
                                <div className="flex justify-between items-start mb-4">
                                    <img src={getFaviconUrl(c.dpo_email)} alt={c.company_name.charAt(0)} className="w-12 h-12 rounded-xl shadow-md border border-gray-100 object-contain p-1" onError={(e) => { e.target.onerror = null; e.target.src = "https://placehold.co/48x48/E0E7FF/4F46E5?text=" + c.company_name.charAt(0).toUpperCase(); }} />
                                    {hasNewReply ? <span className="bg-indigo-100 text-indigo-700 px-2 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wide flex items-center gap-1 animate-pulse"><Mail className='w-3 h-3'/> New Reply</span> : c.status === 'completed' ? <span className="bg-green-100 text-green-700 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide flex items-center gap-1"><Check className='w-3 h-3'/> Done</span> : <span className="bg-yellow-100 text-yellow-700 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide">Pending</span>}
                                </div>
                                <h3 className="font-bold text-gray-900 text-lg mb-1">{c.company_name}</h3>
                                <p className="text-gray-400 text-xs font-mono mb-4 truncate">{c.dpo_email}</p>
                                {hasNewReply && <div className="mb-4 bg-indigo-50 p-2 rounded-lg text-xs text-indigo-800 border border-indigo-100 italic truncate">" {lastMsg.subject} "</div>}
                                <div className="pt-4 border-t border-gray-100 flex justify-between items-center text-xs text-gray-500 font-medium"><span>Sent: {c.sent_date !== 'N/A' ? c.sent_date : 'N/A'}</span><span className="flex items-center gap-1 font-bold text-gray-600">{c.days_elapsed > -1 ? <><Clock className="w-3.5 h-3.5"/> {c.days_elapsed} days</> : 'Date N/A'}</span></div>
                            </div>
                        );
                    })}
                </div>
                {cases.length === 0 && <div className="text-center py-20 text-gray-400 font-medium">No active cases.</div>}
            </div>
        )}
        
        {activeTab === 'settings' && (
             <div className="flex-1 overflow-y-auto p-12 max-w-3xl mx-auto animate-in fade-in slide-in-from-left duration-300">
                 <h1 className="text-2xl font-bold mb-8 text-gray-800">Settings</h1>
                 <div className="glass-panel p-8 rounded-3xl space-y-6 mb-8 border border-white/60">
                    <h3 className="font-bold text-gray-900">User Profile</h3>
                    <div className="grid gap-4">
                        <input type="text" value={userProfile.full_name||''} onChange={(e)=>setUserProfile({...userProfile, full_name:e.target.value})} className="w-full p-3 bg-white/50 border border-gray-200 rounded-xl outline-none" placeholder="Full Name"/>
                        <input type="text" value={userProfile.address||''} onChange={(e)=>setUserProfile({...userProfile, address:e.target.value})} className="w-full p-3 bg-white/50 border border-gray-200 rounded-xl outline-none" placeholder="Address"/>
                        <input type="text" value={userProfile.city||''} onChange={(e)=>setUserProfile({...userProfile, city:e.target.value})} className="w-full p-3 bg-white/50 border border-gray-200 rounded-xl outline-none" placeholder="City"/>
                    </div>
                    <button onClick={handleUpdateProfile} className="btn-primary px-6 py-2.5 rounded-xl font-bold">Save Changes</button>
                 </div>
                 <div className="glass-panel p-8 rounded-3xl border-red-100">
                     <h2 className="font-bold text-red-600 mb-4 flex items-center gap-2"><AlertTriangle className="w-5 h-5"/> Danger Zone</h2>
                     <button onClick={handleResetDB} className="border border-red-200 text-red-600 px-4 py-2 rounded-xl font-bold hover:bg-red-50 transition">Reset Database</button>
                 </div>
             </div>
        )}
      </div>
    </div>
  );
}

function LoginScreen({ onLogin }) {
    const [email, setEmail] = useState("");
    const [pwd, setPwd] = useState("");
    const [loading, setLoading] = useState(false);
    return (
        <div className="h-screen flex items-center justify-center">
            <div className="light-bg"><div className="orb orb-1"></div><div className="orb orb-2"></div></div>
            <form onSubmit={async(e)=>{e.preventDefault(); setLoading(true); await onLogin(email, pwd); setLoading(false);}} className="glass-panel p-10 rounded-3xl shadow-xl w-[440px] space-y-8 border border-white/60">
                <div className="text-center"><div className="w-20 h-20 flex items-center justify-center text-indigo-600 bg-white rounded-2xl shadow-md mx-auto mb-6"><Shield className="w-10 h-10"/></div><h1 className="text-3xl font-extrabold text-gray-800 mb-2">DELETRR</h1></div>
                <div className="space-y-4">
                    <input type="email" value={email} onChange={e=>setEmail(e.target.value)} className="w-full p-4 bg-white/50 border border-gray-200 rounded-xl font-medium outline-none" placeholder="Email"/>
                    <input type="password" value={pwd} onChange={e=>setPwd(e.target.value)} className="w-full p-4 bg-white/50 border border-gray-200 rounded-xl font-mono outline-none" placeholder="App Password"/>
                </div>
                <button disabled={loading} className="btn-primary w-full py-4 rounded-xl font-bold text-lg shadow-lg">{loading ? "..." : "Connect"}</button>
            </form>
        </div>
    );
}

function NavButton({ active, onClick, icon: Icon, label, count }) {
    return <button onClick={onClick} className={`w-full flex justify-between items-center px-4 py-3 rounded-xl mb-1 transition-all ${active ? 'bg-white text-indigo-600 font-bold shadow-sm' : 'text-gray-500 hover:bg-white/50'}`}><div className="flex items-center gap-3"><Icon className="w-5 h-5"/><span className="text-sm">{label}</span></div>{count && <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${active ? 'bg-indigo-50 text-indigo-700' : 'bg-gray-200 text-gray-500'}`}>{count}</span>}</button>;
}

function FilterTabs({ current, onChange, counts }) {
    const tabs = [{id:'ALL', label:'All'}, {id:'DELETE', label:'Cleanup'}, {id:'RGPD_UNSUB', label:'GDPR'}, {id:'KEEP', label:'Legit'}];
    return <div className="flex gap-2 mb-6">{tabs.map(t => <button key={t.id} onClick={()=>onChange(t.id)} className={`px-5 py-2.5 rounded-full text-xs font-bold transition-all border ${current===t.id ? 'bg-gray-800 text-white border-gray-800 shadow-md' : 'bg-white text-gray-500 border-gray-200 hover:border-gray-300'}`}>{t.label} <span className={`ml-1 opacity-70 ${current===t.id?'text-gray-300':'text-gray-400'}`}>{counts[t.id]}</span></button>)}</div>;
}