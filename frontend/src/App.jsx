import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { 
  Activity, Server, AlertTriangle, ShieldCheck, 
  Cpu, Terminal, CheckCircle2, Sparkles, X, Check, ArrowRight,
  Send, Bot, Search, Filter, Monitor, Trash2, Layers, AlertCircle,
  HardDrive, FileDown, Play, Power, CheckCircle, RefreshCw,
  User as UserIcon, Sliders, Eye, EyeOff, ShieldAlert, Clock,
  Users, UserPlus, Lock, Key, Shield, FileText, ToggleLeft, ToggleRight,
  Zap, Radio, WifiOff, Wifi, Code, Copy, CheckSquare, ChevronDown, ChevronUp
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid 
} from 'recharts';

const API_BASE = import.meta.env.VITE_API_URL || `http://${window.location.hostname}:8000/api/v1`;

const WIDGET_LABELS = {
  kpiCards: "Top Summary KPI Cards",
  wolController: "Interactive Remote WOL Terminal Station",
  telemetryChart: "Real-Time Telemetry Line Chart",
  storageBreakdown: "Storage & System Drive Breakdown",
  remoteHub: "Remote Maintenance & Command Console",
  systemHealth: "System Health (Services / Containers / Sensors / GPU)",
  taskManager: "Live Process Task Manager",
  nodeInventory: "Infrastructure Node Inventory Table",
  incidentsTable: "Operational Incidents & AI RCA Diagnostic"
};

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem('token') || '');
  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const saved = localStorage.getItem('user_profile');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  
  const [machines, setMachines] = useState([]);
  const [wolDevices, setWolDevices] = useState([]);
  const [selectedMachine, setSelectedMachine] = useState(null);
  const [metricsHistory, setMetricsHistory] = useState([]);
  const [liveProcesses, setLiveProcesses] = useState([]);
  const [extendedMetrics, setExtendedMetrics] = useState(null);
  const [chartRange, setChartRange] = useState('live');
  const [historyData, setHistoryData] = useState([]);
  const [networkDevices, setNetworkDevices] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanSubnet, setScanSubnet] = useState('');
  const [scanMsg, setScanMsg] = useState('');
  const [deviceFilter, setDeviceFilter] = useState('ALL');
  const [rangeFilter, setRangeFilter] = useState('ALL');
  const [savedRanges, setSavedRanges] = useState([]);
  const [newRangeName, setNewRangeName] = useState('');
  const [inventory, setInventory] = useState(null);
  const [invMachineId, setInvMachineId] = useState('');
  const [swFilter, setSwFilter] = useState('');
  const [softwareQuery, setSoftwareQuery] = useState('');
  const [softwareResults, setSoftwareResults] = useState([]);
  const [assets, setAssets] = useState([]);
  const [assetCoverage, setAssetCoverage] = useState(null);
  const [assetModal, setAssetModal] = useState(null);
  const [invAssetTab, setInvAssetTab] = useState('BOTH');
  const [unregFilter, setUnregFilter] = useState('ALL');
  const [storageDrives, setStorageDrives] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [error, setError] = useState('');
  const [notification, setNotification] = useState('');

  const [activeView, setActiveView] = useState('MONITORING');
  const [nodeSectionTab, setNodeSectionTab] = useState('ALL');
  const [isWolSectionOpen, setIsWolSectionOpen] = useState(false);

  // Interactive WOL Console States
  const [selectedWolTarget, setSelectedWolTarget] = useState(null);
  const [wolGeneratedCmd, setWolGeneratedCmd] = useState('');
  const [wolConsoleLogs, setWolConsoleLogs] = useState([]);
  const [isExecutingWol, setIsExecutingWol] = useState(false);
  const [globalSearchQuery, setGlobalSearchQuery] = useState('');

  // Admin Console States
  const [usersList, setUsersList] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [isAdminUserModalOpen, setIsAdminUserModalOpen] = useState(false);
  const [editingUserId, setEditingUserId] = useState(null);
  const [userFormData, setUserFormData] = useState({
    email: '', full_name: '', password: '', role: 'OPERATOR',
    widget_permissions: {
      kpiCards: true, wolController: true, telemetryChart: true,
      storageBreakdown: true, remoteHub: true, taskManager: true, 
      nodeInventory: true, incidentsTable: true
    }
  });

  // Remote Shell Console Terminal State
  const [remoteCommand, setRemoteCommand] = useState('');
  const [isExecutingCmd, setIsExecutingCmd] = useState(false);
  const [consoleOutput, setConsoleOutput] = useState('');

  // Search & Filter States
  const [procSearch, setProcSearch] = useState('');
  const [procSortKey, setProcSortKey] = useState('cpu');
  const [procSortOrder, setProcSortOrder] = useState('desc');
  const [incidentStatusFilter, setIncidentStatusFilter] = useState('ALL');
  const [resolvingIncident, setResolvingIncident] = useState(null);
  const [resolutionText, setResolutionText] = useState('');

  // Floating AI Chat State
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    { sender: 'bot', text: 'Hello! I am your AI SRE Assistant. Ask me anything regarding node metrics, hanging processes, incident root causes, or power maintenance.' }
  ]);
  const [inputMsg, setInputMsg] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef(null);

  const showToast = (msg) => {
    setNotification(msg);
    setTimeout(() => setNotification(''), 4500);
  };

  const hasPerm = (permName) => {
    if (!currentUser) return false;
    if (currentUser.role === 'ADMIN') return true;
    return currentUser.permissions?.includes(permName);
  };

  const isWidgetAllowed = (widgetKey) => {
    if (!currentUser) return true;
    if (currentUser.role === 'ADMIN') return true;
    return currentUser.widget_permissions?.[widgetKey] !== false;
  };

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setError('');
    setIsLoggingIn(true);
    try {
      const params = new URLSearchParams();
      params.append('username', email.trim());
      params.append('password', password.trim());
      
      const res = await axios.post(`${API_BASE}/auth/login`, params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });

      const newToken = res.data.access_token;
      const userProfile = res.data.user;

      if (newToken) {
        localStorage.setItem('token', newToken);
        localStorage.setItem('user_profile', JSON.stringify(userProfile));
        setToken(newToken);
        setCurrentUser(userProfile);
        setActiveView('MONITORING');
        showToast(`Welcome, ${userProfile.full_name || userProfile.email}!`);
        fetchData(newToken);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user_profile');
    setToken('');
    setCurrentUser(null);
  };

  const fetchData = async (activeToken = token) => {
    if (!activeToken) return;
    try {
      const [machRes, wolRes] = await Promise.all([
        axios.get(`${API_BASE}/agents/machines`, { headers: { Authorization: `Bearer ${activeToken}` } }),
        axios.get(`${API_BASE}/wol/devices`, { headers: { Authorization: `Bearer ${activeToken}` } }).catch(() => ({ data: [] }))
      ]);
      
      const fetchedMachines = machRes.data || [];
      const fetchedWol = wolRes.data || [];
      setMachines(fetchedMachines);
      setWolDevices(fetchedWol);
      
      if (fetchedMachines.length > 0) {
        setSelectedMachine((prev) => {
          if (!prev) return fetchedMachines[0];
          const exists = fetchedMachines.find(m => m.id === prev.id);
          return exists || fetchedMachines[0];
        });
      }

      if (fetchedWol.length > 0) {
        setSelectedWolTarget((prev) => {
          if (!prev) return fetchedWol[0];
          const exists = fetchedWol.find(w => w.id === prev.id);
          return exists || fetchedWol[0];
        });
      }
      
      fetchIncidents(activeToken);
    } catch (err) {
      if (err.response?.status === 401) handleLogout();
    }
  };

  useEffect(() => {
    if (selectedWolTarget) {
      const mac = selectedWolTarget.mac_address || "70:5A:0F:4C:47:D5";
      const bcast = selectedWolTarget.subnet_broadcast || "255.255.255.255";
      const cmd = `$mac="${mac}";$m=($mac -split '[:-]'|%{[Convert]::ToByte($_,16)});$p=[byte[]]((0..5|%{255})+(1..16|%{$m}));$c=New-Object Net.Sockets.UdpClient;$c.EnableBroadcast=$true;$c.Send($p,$p.Length,"${bcast}",9);$c.Close();Write-Host "WoL Magic Packet successfully sent to $mac via ${bcast}"`;
      setWolGeneratedCmd(cmd);
    }
  }, [selectedWolTarget]);

  const fetchIncidents = async (activeToken = token) => {
    if (!activeToken || !hasPerm('incidents.view')) return;
    try {
      const res = await axios.get(`${API_BASE}/incidents/`, { headers: { Authorization: `Bearer ${activeToken}` } });
      setIncidents(res.data || []);
    } catch (err) {
      console.error(err);
    }
  };

  const RANGE_HOURS = { '24h': 24, '7d': 168, '30d': 720 };

  const fetchHistory = async (machineId, hours, activeToken = token) => {
    if (!activeToken || !machineId) return;
    try {
      const res = await axios.get(`${API_BASE}/agents/machines/${machineId}/history?hours=${hours}`, { headers: { Authorization: `Bearer ${activeToken}` } });
      setHistoryData(res.data || []);
    } catch (e) { setHistoryData([]); }
  };

  const fetchNetworkDevices = async (activeToken = token) => {
    if (!activeToken) return;
    try {
      const res = await axios.get(`${API_BASE}/network/devices`, { headers: { Authorization: `Bearer ${activeToken}` } });
      setNetworkDevices(res.data || []);
    } catch (e) { setNetworkDevices([]); }
  };

  const runNetworkScan = async (targetOverride) => {
    const target = (targetOverride !== undefined ? targetOverride : scanSubnet) || null;
    setIsScanning(true);
    setScanMsg('Scanning the network — this can take a few seconds...');
    try {
      const res = await axios.post(`${API_BASE}/network/scan`, { subnet: target }, { headers: { Authorization: `Bearer ${token}` } });
      setScanMsg(`Found ${res.data.count} device(s) on ${res.data.subnet}.`);
      await fetchNetworkDevices();
    } catch (e) {
      setScanMsg('Scan failed: ' + (e.response?.data?.detail || e.message));
    } finally {
      setIsScanning(false);
    }
  };

  const fetchRanges = async (activeToken = token) => {
    if (!activeToken) return;
    try {
      const res = await axios.get(`${API_BASE}/network/ranges`, { headers: { Authorization: `Bearer ${activeToken}` } });
      setSavedRanges(res.data || []);
    } catch (e) { setSavedRanges([]); }
  };

  const saveRange = async () => {
    if (!newRangeName.trim() || !scanSubnet.trim()) { setScanMsg('Type a range in the box and a name, then click Save.'); return; }
    try {
      await axios.post(`${API_BASE}/network/ranges`, { name: newRangeName, target: scanSubnet }, { headers: { Authorization: `Bearer ${token}` } });
      setNewRangeName('');
      await fetchRanges();
      setScanMsg('Range saved.');
    } catch (e) { setScanMsg('Could not save range: ' + (e.response?.data?.detail || e.message)); }
  };

  const deleteRange = async (id) => {
    try { await axios.delete(`${API_BASE}/network/ranges/${id}`, { headers: { Authorization: `Bearer ${token}` } }); await fetchRanges(); } catch (e) {}
  };

  const scanRange = (target) => { setScanSubnet(target); runNetworkScan(target); };

  const exportCSV = async () => {
    try {
      const res = await axios.get(`${API_BASE}/network/devices/export`, { headers: { Authorization: `Bearer ${token}` }, responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/csv' }));
      const a = document.createElement('a');
      a.href = url; a.download = 'asset-inventory.csv';
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (e) { setScanMsg('Export failed: ' + (e.response?.data?.detail || e.message)); }
  };

  const fetchInventory = async (machineId) => {
    if (!machineId || !token) { setInventory(null); return; }
    try {
      const res = await axios.get(`${API_BASE}/agents/machines/${machineId}/inventory`, { headers: { Authorization: `Bearer ${token}` } });
      setInventory(res.data);
    } catch (e) { setInventory(null); }
  };

  const searchSoftware = async () => {
    if (!softwareQuery.trim()) { setSoftwareResults([]); return; }
    try {
      const res = await axios.get(`${API_BASE}/agents/software/search?q=${encodeURIComponent(softwareQuery)}`, { headers: { Authorization: `Bearer ${token}` } });
      setSoftwareResults(res.data || []);
    } catch (e) { setSoftwareResults([]); }
  };

  const authHdr = () => ({ headers: { Authorization: `Bearer ${token}` } });

  const fetchAssets = async () => {
    try { const r = await axios.get(`${API_BASE}/assets`, authHdr()); setAssets(r.data || []); } catch (e) { setAssets([]); }
  };
  const fetchCoverage = async () => {
    try { const r = await axios.get(`${API_BASE}/assets/coverage`, authHdr()); setAssetCoverage(r.data); } catch (e) { setAssetCoverage(null); }
  };
  const syncAssets = async () => {
    try { await axios.post(`${API_BASE}/assets/sync`, {}, authHdr()); await fetchAssets(); await fetchCoverage(); } catch (e) {}
  };
  const saveAsset = async () => {
    const body = { ...assetModal };
    const id = body.id; delete body.id; delete body.machine_id;
    try {
      if (id) await axios.patch(`${API_BASE}/assets/${id}`, body, authHdr());
      else await axios.post(`${API_BASE}/assets`, body, authHdr());
      setAssetModal(null); await fetchAssets(); await fetchCoverage();
    } catch (e) {}
  };
  const deleteAsset = async (id) => {
    try { await axios.delete(`${API_BASE}/assets/${id}`, authHdr()); await fetchAssets(); await fetchCoverage(); } catch (e) {}
  };
  const exportAssets = async () => {
    try {
      const r = await axios.get(`${API_BASE}/assets/export`, { ...authHdr(), responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([r.data], { type: 'text/csv' }));
      const a = document.createElement('a'); a.href = url; a.download = 'asset-register.csv';
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } catch (e) {}
  };

  const fetchNodeDetails = async (machineId, activeToken = token) => {
    if (!activeToken || !machineId) return;
    try {
      const [metricsRes, procsRes] = await Promise.all([
        axios.get(`${API_BASE}/agents/machines/${machineId}/metrics`, { headers: { Authorization: `Bearer ${activeToken}` } }),
        axios.get(`${API_BASE}/agents/machines/${machineId}/processes`, { headers: { Authorization: `Bearer ${activeToken}` } })
      ]);
      const rawMetrics = metricsRes.data || [];
      setMetricsHistory(rawMetrics);
      setLiveProcesses(procsRes.data || []);

      try {
        const extRes = await axios.get(`${API_BASE}/agents/machines/${machineId}/extended`, { headers: { Authorization: `Bearer ${activeToken}` } });
        setExtendedMetrics(extRes.data || null);
      } catch (e) { setExtendedMetrics(null); }

      const targetMachine = machines.find(m => m.id === machineId) || selectedMachine;
      const isLinux = targetMachine?.os_name?.toLowerCase().includes('linux') || targetMachine?.os_name?.toLowerCase().includes('ubuntu');

      if (rawMetrics.length > 0 && rawMetrics[rawMetrics.length - 1].drives && rawMetrics[rawMetrics.length - 1].drives.length > 0) {
        setStorageDrives(rawMetrics[rawMetrics.length - 1].drives);
      } else if (rawMetrics.length > 0) {
        const last = rawMetrics[rawMetrics.length - 1];
        const defaultMount = isLinux ? "/" : "C:\\";
        const total = last.disk_total_gb || 0;
        const used = last.disk_used_gb || 0;
        const free = Math.max(0, total - used).toFixed(2);
        
        setStorageDrives([{
          mount: defaultMount,
          device: isLinux ? "/dev/sda1" : "Local Disk (C:)",
          total_gb: total,
          used_gb: used,
          free_gb: free,
          percent: last.disk_percent || 0
        }]);
      } else {
        setStorageDrives([]);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchAdminData = async () => {
    if (!token || !hasPerm('admin.users_manage')) return;
    try {
      const [usersRes, logsRes] = await Promise.all([
        axios.get(`${API_BASE}/admin/users`, { headers: { Authorization: `Bearer ${token}` } }),
        axios.get(`${API_BASE}/admin/audit-logs`, { headers: { Authorization: `Bearer ${token}` } })
      ]);
      setUsersList(usersRes.data || []);
      setAuditLogs(logsRes.data || []);
    } catch (err) {
      console.error(err);
    }
  };

  const handleExecuteWolCommand = async () => {
    if (!hasPerm('wol.execute')) {
      alert("Unauthorized: Missing 'wol.execute' permission.");
      return;
    }
    if (!selectedWolTarget) return;

    if (!selectedWolTarget.has_valid_mac) {
      alert(`Target node ${selectedWolTarget.hostname} does not have a physical MAC address registered.`);
      return;
    }

    setIsExecutingWol(true);
    const nowStr = new Date().toLocaleTimeString();
    
    setWolConsoleLogs([
      `[${nowStr}] [STEP 1] Validating target node: ${selectedWolTarget.hostname}...`,
      `[${nowStr}] [STEP 2] Physical MAC: ${selectedWolTarget.mac_address} | Subnet Broadcast: ${selectedWolTarget.subnet_broadcast}`,
      `[${nowStr}] [STEP 3] Assembling 102-Byte Layer-2 Synchronization Frame (6x 0xFF + 16x MAC)...`,
      `[${nowStr}] [STEP 4] Multi-Engine Broadcast: Firing via Linux Native wakeonlan & Python UDP Sockets...`
    ]);

    try {
      const res = await axios.post(`${API_BASE}/wol/wake/${selectedWolTarget.id}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setTimeout(() => {
        const completionTime = new Date().toLocaleTimeString();
        const logsList = res.data.logs || [];
        setWolConsoleLogs(prev => [
          ...prev,
          ...logsList.map(l => `[${completionTime}] [ENGINE] ${l}`),
          `[${completionTime}] [STEP 5] [+] Magic Packet payload successfully blasted! State changed to 'BOOTING'...`,
          `[${completionTime}] [OUTPUT] ${res.data.message || 'Magic Packet dispatched successfully.'}`
        ]);
        setIsExecutingWol(false);
        showToast(`⚡ Multi-Engine Wake Signal blasted to ${selectedWolTarget.hostname}!`);
        fetchData();
      }, 600);

    } catch (err) {
      const failTime = new Date().toLocaleTimeString();
      setWolConsoleLogs(prev => [
        ...prev,
        `[${failTime}] [ERROR] Execution failed: ${err.response?.data?.detail || err.message}`
      ]);
      setIsExecutingWol(false);
    }
  };

  const handleDownloadPDF = async (incidentId, incidentCode) => {
    try {
      showToast(`Generating PDF report for ${incidentCode}...`);
      const response = await axios.get(`${API_BASE}/incidents/${incidentId}/export-pdf`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `Incident_Report_${incidentCode}.pdf`;
      link.click();
      showToast(`Incident PDF downloaded successfully!`);
    } catch (err) {
      alert("Failed to export PDF report.");
    }
  };

  const handleAnalyzeWithAI = async (incidentId) => {
    try {
      showToast(`Invoking AI Root Cause Analysis...`);
      await axios.post(`${API_BASE}/incidents/${incidentId}/analyze`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchIncidents();
      showToast(`AI RCA completed!`);
    } catch (err) {
      alert("Failed to run AI diagnostic.");
    }
  };

  const handleConfirmResolve = async () => {
    if (!resolvingIncident) return;
    try {
      await axios.patch(`${API_BASE}/incidents/${resolvingIncident.id}/status`, {
        status: "RESOLVED",
        resolution_notes: resolutionText.trim()
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setResolvingIncident(null);
      setResolutionText('');
      fetchIncidents();
      showToast(`Incident marked RESOLVED with audit record.`);
    } catch (err) {
      alert("Failed to resolve incident.");
    }
  };

  const handleSendChatMessage = async (e) => {
    e.preventDefault();
    if (!inputMsg.trim() || chatLoading) return;
    const userText = inputMsg;
    setInputMsg('');
    setChatMessages(prev => [...prev, { sender: 'user', text: userText }]);
    setChatLoading(true);

    try {
      const res = await axios.post(`${API_BASE}/ai/chat`, {
        message: userText,
        machine_context: selectedMachine ? {
          hostname: selectedMachine.hostname,
          os: selectedMachine.os_name,
          user: selectedMachine.logged_in_user,
          cpu: metricsHistory.length > 0 ? metricsHistory[metricsHistory.length - 1].cpu_percent : 0
        } : null
      }, { headers: { Authorization: `Bearer ${token}` } });

      setChatMessages(prev => [...prev, { sender: 'bot', text: res.data.response || "Analysis complete." }]);
    } catch {
      setChatMessages(prev => [...prev, { sender: 'bot', text: "AI Assistant temporarily busy. Please retry." }]);
    } finally {
      setChatLoading(false);
      chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleOpenCreateUser = () => {
    setEditingUserId(null);
    setUserFormData({
      email: '', full_name: '', password: '', role: 'OPERATOR',
      widget_permissions: {
        kpiCards: true, wolController: true, telemetryChart: true,
        storageBreakdown: true, remoteHub: true, taskManager: true, 
        nodeInventory: true, incidentsTable: true
      }
    });
    setIsAdminUserModalOpen(true);
  };

  const handleOpenEditUser = (u) => {
    setEditingUserId(u.id);
    setUserFormData({
      email: u.email, full_name: u.full_name || '', password: '', role: u.role,
      widget_permissions: u.widget_permissions || {}
    });
    setIsAdminUserModalOpen(true);
  };

  const handleSaveUser = async (e) => {
    e.preventDefault();
    try {
      if (editingUserId) {
        await axios.patch(`${API_BASE}/admin/users/${editingUserId}`, userFormData, {
          headers: { Authorization: `Bearer ${token}` }
        });
        showToast(`User updated successfully!`);
      } else {
        await axios.post(`${API_BASE}/admin/users`, userFormData, {
          headers: { Authorization: `Bearer ${token}` }
        });
        showToast(`New user created successfully!`);
      }
      setIsAdminUserModalOpen(false);
      fetchAdminData();
    } catch (err) {
      alert(err.response?.data?.detail || "Operation failed.");
    }
  };

  const handleToggleUserActive = async (u) => {
    try {
      await axios.patch(`${API_BASE}/admin/users/${u.id}`, { is_active: !u.is_active }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      showToast(`User status updated.`);
      fetchAdminData();
    } catch (err) {
      alert("Failed to update status.");
    }
  };

  const handleKillProcess = async (pid, procName) => {
    if (!hasPerm('processes.kill')) return alert("Unauthorized.");
    if (!window.confirm(`⚠️ Terminate PID ${pid} (${procName})?`)) return;
    try {
      await axios.post(`${API_BASE}/agents/machines/${selectedMachine.id}/kill-process?pid=${pid}`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      showToast(`Kill instruction queued.`);
      fetchNodeDetails(selectedMachine.id);
    } catch (err) {
      alert("Failed to kill process.");
    }
  };

  const handleExecuteRemoteAction = async (cmdType, extraData = {}) => {
    if (!hasPerm('remote_ops.execute')) return alert("Unauthorized.");
    if (!selectedMachine) return;
    setIsExecutingCmd(true);
    setConsoleOutput(`[*] Dispatched '${cmdType}' to ${selectedMachine.hostname}...`);
    try {
      const res = await axios.post(`${API_BASE}/agents/machines/${selectedMachine.id}/remote-action`, {
        command_type: cmdType,
        ...extraData
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const cmdId = res.data.command_id;
      let attempts = 0;
      const pollTimer = setInterval(async () => {
        attempts++;
        try {
          const outRes = await axios.get(`${API_BASE}/agents/machines/${selectedMachine.id}/command-output/${cmdId}`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          if (outRes.data.output && outRes.data.output !== "Executing on remote host...") {
            setConsoleOutput(`[Output from ${selectedMachine.hostname}]:\n` + outRes.data.output);
            setIsExecutingCmd(false);
            clearInterval(pollTimer);
          } else if (attempts > 12) {
            setConsoleOutput(`[TIMEOUT] Dispatched.`);
            setIsExecutingCmd(false);
            clearInterval(pollTimer);
          }
        } catch (e) {
          clearInterval(pollTimer);
          setIsExecutingCmd(false);
        }
      }, 1000);
    } catch (err) {
      setConsoleOutput(`[ERROR] ${err.message}`);
      setIsExecutingCmd(false);
    }
  };

  const filteredWolDevices = wolDevices.filter((dev) => {
    const q = globalSearchQuery.toLowerCase();
    const matchSearch = 
      dev.hostname.toLowerCase().includes(q) ||
      (dev.ip_address && dev.ip_address.toLowerCase().includes(q)) ||
      (dev.mac_address && dev.mac_address.toLowerCase().includes(q)) ||
      (dev.logged_in_user && dev.logged_in_user.toLowerCase().includes(q));

    if (nodeSectionTab === 'ONLINE') return matchSearch && dev.is_online;
    if (nodeSectionTab === 'OFFLINE') return matchSearch && !dev.is_online;
    return matchSearch;
  });

  const filteredMachines = machines.filter((m) => {
    const q = globalSearchQuery.toLowerCase();
    return m.hostname.toLowerCase().includes(q) ||
      (m.ip_address && m.ip_address.toLowerCase().includes(q)) ||
      (m.mac_address && m.mac_address.toLowerCase().includes(q)) ||
      (m.logged_in_user && m.logged_in_user.toLowerCase().includes(q));
  });

  const filteredProcesses = liveProcesses
    .filter((p) => {
      const term = procSearch.toLowerCase();
      return p.name.toLowerCase().includes(term) || p.pid.toString().includes(term);
    })
    .sort((a, b) => {
      let valA = procSortKey === 'cpu' ? a.cpu_percent : a.memory_percent;
      let valB = procSortKey === 'cpu' ? b.cpu_percent : b.memory_percent;
      return procSortOrder === 'desc' ? valB - valA : valA - valB;
    });

  const filteredIncidents = incidents.filter((inc) => {
    if (incidentStatusFilter === 'OPEN') return inc.status === 'OPEN' || inc.status === 'IN_PROGRESS';
    if (incidentStatusFilter === 'RESOLVED') return inc.status === 'RESOLVED' || inc.status === 'CLOSED';
    return true;
  });

  const latestMetric = metricsHistory.length > 0 ? metricsHistory[metricsHistory.length - 1] : null;

  const catOf = (t) => {
    t = (t || '').toLowerCase();
    if (t.includes('mobile')) return 'MOBILE';
    if (t.includes('network')) return 'NETWORK';
    if (t.includes('virtual')) return 'VM';
    if (t.includes('computer')) return 'COMPUTER';
    if (t.includes('iot') || t.includes('smart')) return 'IOT';
    return 'OTHER';
  };
  const ASSET_COLS = [
    ['asset_no', 'Asset No'], ['category', 'Asset Category'], ['sub_category', 'Sub Category'],
    ['host_name', 'Host Name'], ['make', 'Make'], ['model', 'Model'],
    ['allocation_type', 'Type of Allocation'], ['allocation_purpose', 'Purpose of Allocation'],
    ['owned_by_emp_id', 'Owned By Employee ID'], ['owned_by_emp_name', 'Owned By Employee Name'],
    ['workstation_number', 'Work Station Number'],
    ['serial_no', 'SerialNo'], ['processor_type', 'Processor Type'], ['ram', 'RAM'],
    ['hard_disk_size', 'Hard Disk Size'], ['os_architecture', 'OS Architecture'],
    ['os_version', 'OS Version'], ['os_edition', 'OS Edition'], ['license_key', 'Windows License Key'],
    ['warranty_start', 'Warranty Start'], ['warranty_end', 'Warranty End'],
  ];

  const importanceRank = (t) => {
    t = (t || '').toLowerCase();
    if (t.includes('computer') || t.includes('windows') || t.includes('linux server')) return 0;
    if (t.includes('linux') || t.includes('host')) return 1;
    if (t.includes('virtual')) return 2;
    if (t.includes('printer') || t.includes('camera') || t.includes('iot')) return 3;
    if (t.includes('network') || t.includes('router')) return 4;
    if (t.includes('mobile') || t.includes('private')) return 5;
    return 3;
  };

  const filteredDevices = networkDevices.filter((d) =>
    (deviceFilter === 'ALL' || catOf(d.device_type) === deviceFilter) &&
    (rangeFilter === 'ALL' || (d.source_subnet || '') === rangeFilter));
  const currentCpu = latestMetric ? latestMetric.cpu_percent : 0;
  const isCpuHigh = currentCpu >= 80;

  useEffect(() => {
    if (token) {
      fetchData();
      if (activeView === 'ADMIN_CONSOLE') fetchAdminData();
      const interval = setInterval(() => {
        fetchData();
        if (selectedMachine) fetchNodeDetails(selectedMachine.id);
        if (activeView === 'ADMIN_CONSOLE') fetchAdminData();
      }, 3500);
      return () => clearInterval(interval);
    }
  }, [token, selectedMachine?.id, activeView]);

  useEffect(() => {
    if (chartRange !== 'live' && selectedMachine) {
      fetchHistory(selectedMachine.id, RANGE_HOURS[chartRange]);
    }
  }, [chartRange, selectedMachine?.id]);

  if (!token) {
    return (
      <div className="min-h-screen bg-[#0b0f19] flex items-center justify-center p-4">
        <div className="bg-[#1e293b] border border-[#334155] rounded-2xl p-8 max-w-md w-full shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <Activity className="w-8 h-8 text-teal-400" />
            <div>
              <h1 className="text-xl font-bold text-white">AI-ITMonitor Pro</h1>
              <p className="text-xs text-slate-400">Enterprise SRE & Observability Console</p>
            </div>
          </div>
          {error && <div className="p-3 mb-4 bg-red-950/60 border border-red-500/50 text-red-300 rounded text-xs">{error}</div>}
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Corporate Email</label>
              <input type="text" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full bg-[#0f172a] border border-[#334155] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-teal-500" />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Password</label>
              <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className="w-full bg-[#0f172a] border border-[#334155] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-teal-500" />
            </div>
            <button type="submit" disabled={isLoggingIn} className="w-full bg-teal-600 hover:bg-teal-500 text-white font-semibold py-2.5 rounded-lg text-sm transition disabled:opacity-50">
              {isLoggingIn ? 'Authenticating...' : 'Sign In to Estate'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col relative">
      {notification && (
        <div className="fixed top-4 right-4 bg-teal-950 border border-teal-500 text-teal-300 px-4 py-3 rounded-xl shadow-2xl z-50 flex items-center gap-2 text-xs font-medium animate-bounce">
          <CheckCircle2 className="w-4 h-4 text-teal-400" /> {notification}
        </div>
      )}

      {/* Top Navbar */}
      <header className="bg-[#111827] border-b border-[#1f2937] px-6 py-4 flex justify-between items-center">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <Activity className="w-6 h-6 text-teal-400" />
            <span className="font-bold text-lg text-white tracking-wide">AI-ITMonitor Pro</span>
          </div>

          <div className="flex items-center bg-[#0f172a] p-1 rounded-lg border border-[#1e293b] ml-4">
            <button
              onClick={() => setActiveView('MONITORING')}
              className={`text-xs px-3 py-1.5 rounded transition ${
                activeView === 'MONITORING' ? 'bg-teal-600 text-white font-medium shadow' : 'text-slate-400 hover:text-white'
              }`}
            >
              Monitoring Dashboard
            </button>
            {hasPerm('admin.users_manage') && (
              <button
                onClick={() => { setActiveView('ADMIN_CONSOLE'); fetchAdminData(); }}
                className={`text-xs px-3 py-1.5 rounded transition flex items-center gap-1.5 ${
                  activeView === 'ADMIN_CONSOLE' ? 'bg-teal-600 text-white font-medium shadow' : 'text-slate-400 hover:text-white'
                }`}
              >
                <Shield className="w-3.5 h-3.5" /> Main Admin Console
              </button>
            )}
            {hasPerm('telemetry.view') && (
              <button
                onClick={() => { setActiveView('ASSETS'); fetchNetworkDevices(); fetchRanges(); }}
                className={`text-xs px-3 py-1.5 rounded transition flex items-center gap-1.5 ${
                  activeView === 'ASSETS' ? 'bg-teal-600 text-white font-medium shadow' : 'text-slate-400 hover:text-white'
                }`}
              >
                <Radio className="w-3.5 h-3.5" /> Asset Audit
              </button>
            )}
            {hasPerm('telemetry.view') && (
              <button
                onClick={() => { setActiveView('INV_ASSETS'); fetchAssets(); fetchCoverage(); }}
                className={`text-xs px-3 py-1.5 rounded transition flex items-center gap-1.5 ${
                  activeView === 'INV_ASSETS' ? 'bg-teal-600 text-white font-medium shadow' : 'text-slate-400 hover:text-white'
                }`}
              >
                <HardDrive className="w-3.5 h-3.5" /> Inventory & Assets
              </button>
            )}

          </div>
        </div>

        <div className="flex items-center gap-3 text-sm">
          <span className="text-slate-400 flex items-center gap-2 text-xs">
            <ShieldCheck className="w-4 h-4 text-emerald-400" /> {currentUser?.full_name || currentUser?.email} [{currentUser?.role}]
          </span>
          <button onClick={handleLogout} className="text-xs bg-[#1f2937] hover:bg-red-900/50 text-slate-300 px-3 py-1.5 rounded transition border border-[#374151]">
            Logout
          </button>
        </div>
      </header>

      {/* VIEW 1: MONITORING DASHBOARD */}
      {activeView === 'MONITORING' && (
        <main className="p-6 flex-1 space-y-6 max-w-7xl mx-auto w-full mb-16">
          {/* 1. KPI Cards */}
          {isWidgetAllowed('kpiCards') && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-5 shadow-sm">
                <p className="text-xs text-slate-400 font-medium">Total Registered Nodes</p>
                <p className="text-2xl font-bold text-white mt-1">{machines.length}</p>
              </div>
              <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-5 shadow-sm">
                <p className="text-xs text-slate-400 font-medium">Healthy / Online</p>
                <p className="text-2xl font-bold text-emerald-400 mt-1">{wolDevices.filter(m => m.is_online).length}</p>
              </div>
              <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-5 shadow-sm">
                <p className="text-xs text-slate-400 font-medium">Offline (WOL Ready)</p>
                <p className="text-2xl font-bold text-amber-400 mt-1">{wolDevices.filter(m => !m.is_online).length}</p>
              </div>
              <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-5 shadow-sm">
                <p className="text-xs text-slate-400 font-medium">Inspecting Target Node</p>
                <p className="text-lg font-bold text-teal-400 mt-1 truncate">{selectedMachine?.hostname || 'None'}</p>
                <p className="text-[11px] text-slate-400 flex items-center gap-1 mt-0.5">
                  <UserIcon className="w-3 h-3 text-emerald-400" /> Active User: <span className="text-white font-medium">{selectedMachine?.logged_in_user || 'System'}</span>
                </p>
              </div>
            </div>
          )}

          {/* 2. DEDICATED INTERACTIVE WAKE-ON-LAN POWER STATION (COLLAPSIBLE BUTTON TOGGLE) */}
          {isWidgetAllowed('wolController') && (
            <div className="bg-[#131d31] border border-amber-500/40 rounded-2xl overflow-hidden shadow-xl transition">
              <div 
                onClick={() => setIsWolSectionOpen(!isWolSectionOpen)}
                className="p-4 bg-[#0f172a]/80 hover:bg-[#0f172a] cursor-pointer flex justify-between items-center transition border-b border-[#1e293b]"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-amber-950/80 border border-amber-500/40 rounded-xl">
                    <Zap className="w-4 h-4 text-amber-400 fill-amber-400" />
                  </div>
                  <div>
                    <h3 className="font-bold text-white text-sm flex items-center gap-2">
                      Interactive Wake-on-LAN Power Terminal Station
                      <span className="text-[11px] font-normal px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800">
                        Online ({wolDevices.filter(d => d.is_online).length})
                      </span>
                      <span className="text-[11px] font-normal px-2 py-0.5 rounded-full bg-amber-950 text-amber-400 border border-amber-800">
                        Offline ({wolDevices.filter(d => !d.is_online).length})
                      </span>
                    </h3>
                    <p className="text-xs text-slate-400">Multi-Engine Layer-2 Magic Packet Dispatcher (Linux Native + Dynamic Sockets)</p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-xs text-amber-400 font-semibold flex items-center gap-1 bg-amber-950/40 px-3 py-1.5 rounded-lg border border-amber-800/40">
                    {isWolSectionOpen ? 'Hide Power Station' : '⚡ Open Power Station'}
                    {isWolSectionOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </span>
                </div>
              </div>

              {isWolSectionOpen && (
                <div className="space-y-4 p-5">
                  <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-[#1e293b] pb-4">
                    <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
                      {/* Section Tabs */}
                      <div className="flex bg-[#0b0f19] p-1 rounded-lg border border-[#1e293b]">
                        <button
                          onClick={() => setNodeSectionTab('ALL')}
                          className={`text-xs px-2.5 py-1 rounded transition ${nodeSectionTab === 'ALL' ? 'bg-amber-600 text-white font-medium' : 'text-slate-400'}`}
                        >
                          All ({wolDevices.length})
                        </button>
                        <button
                          onClick={() => setNodeSectionTab('ONLINE')}
                          className={`text-xs px-2.5 py-1 rounded transition flex items-center gap-1 ${nodeSectionTab === 'ONLINE' ? 'bg-emerald-600 text-white font-medium' : 'text-slate-400'}`}
                        >
                          <Wifi className="w-3 h-3" /> Online ({wolDevices.filter(d => d.is_online).length})
                        </button>
                        <button
                          onClick={() => setNodeSectionTab('OFFLINE')}
                          className={`text-xs px-2.5 py-1 rounded transition flex items-center gap-1 ${nodeSectionTab === 'OFFLINE' ? 'bg-red-600 text-white font-medium' : 'text-slate-400'}`}
                        >
                          <WifiOff className="w-3 h-3" /> Offline ({wolDevices.filter(d => !d.is_online).length})
                        </button>
                      </div>

                      {/* Search Bar by Hostname, IP, MAC or Username */}
                      <div className="relative flex-1 md:w-60">
                        <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                        <input
                          type="text"
                          placeholder="Search host, user or MAC..."
                          value={globalSearchQuery}
                          onChange={(e) => setGlobalSearchQuery(e.target.value)}
                          className="w-full bg-[#0b0f19] border border-[#334155] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Target Node Selector Dropdown */}
                  <div className="flex items-center gap-3 bg-[#0b0f19] p-3 rounded-xl border border-[#1e293b]">
                    <label className="text-xs text-amber-300 font-semibold flex items-center gap-1.5 whitespace-nowrap">
                      <Monitor className="w-4 h-4 text-amber-400" /> Select Target PC:
                    </label>
                    <select
                      value={selectedWolTarget ? selectedWolTarget.id : ''}
                      onChange={(e) => {
                        const t = wolDevices.find((d) => d.id === parseInt(e.target.value));
                        if (t) setSelectedWolTarget(t);
                      }}
                      className="bg-[#131d31] border border-amber-500/40 text-white text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-amber-400 flex-1 font-semibold"
                    >
                      {filteredWolDevices.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.hostname} [{d.is_online ? 'ONLINE' : 'OFFLINE'}] — User: {d.logged_in_user} | MAC: {d.mac_address || 'Not Registered'}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Dynamic Target Info Badges */}
                  {selectedWolTarget && (
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3 bg-[#0b0f19] p-3.5 rounded-xl border border-[#1e293b] text-xs font-mono">
                      <div>
                        <span className="text-slate-500 block text-[11px]">TARGET HOSTNAME:</span>
                        <span className="text-white font-bold font-sans">{selectedWolTarget.hostname}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[11px]">PHYSICAL MAC ADDRESS:</span>
                        {selectedWolTarget.has_valid_mac ? (
                          <span className="text-teal-400 font-bold">{selectedWolTarget.mac_address}</span>
                        ) : (
                          <span className="text-amber-400/90 font-sans bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/40 text-[11px]">
                            ⚠️ Not Configured (Blank)
                          </span>
                        )}
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[11px]">SUBNET BROADCAST:</span>
                        <span className="text-amber-400 font-bold">{selectedWolTarget.subnet_broadcast}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[11px]">POWER STATE:</span>
                        {selectedWolTarget.is_online ? (
                          <span className="text-emerald-400 font-bold font-sans flex items-center gap-1">
                            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> ONLINE (Running)
                          </span>
                        ) : (
                          <span className="text-amber-400 font-bold font-sans flex items-center gap-1">
                            <Power className="w-3 h-3 text-amber-400" /> OFFLINE (Standby)
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Live Injected PowerShell Command Box */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between items-center text-xs text-slate-300">
                      <span className="font-semibold flex items-center gap-1.5 text-amber-300">
                        <Code className="w-4 h-4 text-amber-400" /> Equivalent Windows PowerShell Script (Dynamic Injection):
                      </span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(wolGeneratedCmd);
                          showToast("PowerShell command copied to clipboard!");
                        }}
                        className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px]"
                      >
                        <Copy className="w-3 h-3" /> Copy Script
                      </button>
                    </div>
                    <textarea
                      rows={3}
                      value={wolGeneratedCmd}
                      onChange={(e) => setWolGeneratedCmd(e.target.value)}
                      className="w-full bg-[#0b0f19] border border-[#334155] rounded-xl p-3 text-xs font-mono text-emerald-400 focus:outline-none focus:border-amber-500 leading-relaxed"
                    />
                  </div>

                  {/* Action Button */}
                  <div className="flex justify-end gap-3">
                    <button
                      onClick={handleExecuteWolCommand}
                      disabled={isExecutingWol || !hasPerm('wol.execute') || !selectedWolTarget?.has_valid_mac}
                      className="bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold px-6 py-2.5 rounded-xl shadow-lg hover:shadow-amber-500/20 transition flex items-center gap-2 text-xs disabled:opacity-50"
                    >
                      {isExecutingWol ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin text-slate-950" /> Blasting Multi-Engine Packet...
                        </>
                      ) : (
                        <>
                          <Zap className="w-4 h-4 fill-slate-950" /> Execute Multi-Engine WOL Signal to {selectedWolTarget?.hostname || 'Target'}
                        </>
                      )}
                    </button>
                  </div>

                  {/* Live Execution Trace Stream Output Console */}
                  {wolConsoleLogs.length > 0 && (
                    <div className="bg-[#0b0f19] border border-teal-800/40 rounded-xl p-4 font-mono text-xs space-y-1.5">
                      <div className="flex justify-between items-center border-b border-[#1e293b] pb-2 text-[11px] text-slate-400">
                        <span className="flex items-center gap-1.5 text-teal-300 font-bold font-sans">
                          <Terminal className="w-3.5 h-3.5 text-teal-400" /> Live WOL Dispatch Engine Trace
                        </span>                        <button onClick={() => setWolConsoleLogs([])} className="text-slate-500 hover:text-white">Clear</button>
                      </div>
                      <div className="max-h-40 overflow-y-auto space-y-1 pt-1">
                        {wolConsoleLogs.map((log, idx) => (
                          <div key={idx} className={`leading-relaxed ${
                            log.includes('[ERROR]') ? 'text-red-400 font-bold' :
                            log.includes('[STEP') ? 'text-sky-300' :
                            log.includes('[+]') || log.includes('[ENGINE]') ? 'text-emerald-400 font-bold' :
                            'text-amber-300'
                          }`}>
                            {log}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* 3. Live Telemetry Chart (UNIQUE DYNAMIC GRADIENT ON HIGH LOAD >= 80%) */}
          {isWidgetAllowed('telemetryChart') && (
            <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-6 shadow-sm">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
                <div>
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Cpu className={`w-5 h-5 ${isCpuHigh ? 'text-red-400 animate-pulse' : 'text-teal-400'}`} />
                    Live Telemetry: {selectedMachine ? `${selectedMachine.hostname} (${selectedMachine.os_name})` : 'Awaiting node...'}
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Real-time multi-resource stream — Active User: <strong className="text-emerald-400">{selectedMachine?.logged_in_user || 'System'}</strong>
                    {isCpuHigh && <span className="ml-2 text-red-400 font-bold animate-pulse">⚠️ HIGH LOAD ALERT (≥80%)</span>}
                  </p>
                </div>

                <div className="flex items-center gap-3 w-full md:w-auto">
                  <label className="text-xs text-slate-400 font-medium flex items-center gap-1.5 whitespace-nowrap">
                    <Monitor className="w-4 h-4 text-teal-400" /> Select Node:
                  </label>
                  <select
                    value={selectedMachine ? selectedMachine.id : ''}
                    onChange={(e) => {
                      const m = machines.find((item) => item.id === parseInt(e.target.value));
                      if (m) setSelectedMachine(m);
                    }}
                    className="bg-[#0f172a] border border-[#334155] text-white text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-teal-500 w-full md:w-64"
                  >
                    {machines.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.hostname} [{m.status}] — User: {m.logged_in_user || 'System'}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex justify-end mb-2" data-role="chart-range-selector">
                <div className="flex items-center gap-1 bg-[#0f172a] border border-[#334155] rounded-lg p-1">
                  {[['live', 'Live'], ['24h', '24h'], ['7d', '7d'], ['30d', '30d']].map(([val, label]) => (
                    <button
                      key={val}
                      onClick={() => setChartRange(val)}
                      className={`text-xs px-2.5 py-1 rounded-md transition ${chartRange === val ? 'bg-teal-500 text-white font-semibold' : 'text-slate-400 hover:text-white'}`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartRange === 'live' ? metricsHistory : historyData}>
                    <defs>
                      <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={isCpuHigh ? "#ef4444" : "#2dd4bf"} stopOpacity={0.4}/>
                        <stop offset="95%" stopColor={isCpuHigh ? "#ef4444" : "#2dd4bf"} stopOpacity={0.0}/>
                      </linearGradient>
                      <linearGradient id="ramGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0}/>
                      </linearGradient>
                      <linearGradient id="diskGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#818cf8" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#818cf8" stopOpacity={0.0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="timestamp" stroke="#64748b" fontSize={11} />
                    <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} unit="%" />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#fff' }} />
                    <Area type="monotone" dataKey="cpu_percent" stroke={isCpuHigh ? "#ef4444" : "#2dd4bf"} strokeWidth={2.5} fillOpacity={1} fill="url(#cpuGradient)" name="CPU Usage %" />
                    <Area type="monotone" dataKey="ram_percent" stroke="#38bdf8" strokeWidth={2} fillOpacity={1} fill="url(#ramGradient)" name="RAM Usage %" />
                    <Area type="monotone" dataKey="disk_percent" stroke="#818cf8" strokeWidth={2} fillOpacity={1} fill="url(#diskGradient)" name="Disk %" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* 4. Storage Breakdown (OS-AWARE DYNAMIC PARTITIONS & FREE SPACE) */}
          {isWidgetAllowed('storageBreakdown') && (
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <HardDrive className="w-4 h-4 text-indigo-400" />
                  System Storage Drive Breakdown ({selectedMachine?.os_name || 'System'})
                </h3>
                <span className="text-[11px] text-slate-400">{storageDrives.length} Partition(s) Detected</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {storageDrives.length > 0 ? (
                  storageDrives.map((drv, idx) => (
                    <div key={idx} className="bg-[#131d31] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-2">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-3">
                          <HardDrive className="w-9 h-9 text-indigo-400 p-2 bg-indigo-950/60 rounded-xl border border-indigo-800" />
                          <div>
                            <p className="text-xs text-slate-300 font-bold">{drv.mount} {drv.device ? `(${drv.device})` : ''}</p>
                            <p className="text-[11px] text-slate-400">Total: {drv.total_gb} GB</p>
                          </div>
                        </div>
                        <span className="text-sm font-bold text-teal-400 font-mono">{drv.percent}% Used</span>
                      </div>

                      {/* Visual Bar */}
                      <div className="w-full bg-[#0b0f19] h-2 rounded-full overflow-hidden border border-[#1e293b]">
                        <div 
                          className={`h-full transition-all duration-500 ${drv.percent > 85 ? 'bg-red-500' : drv.percent > 70 ? 'bg-amber-400' : 'bg-teal-400'}`}
                          style={{ width: `${drv.percent}%` }}
                        ></div>
                      </div>

                      <div className="flex justify-between items-center text-[11px] text-slate-400 pt-1">
                        <span>Used: <strong className="text-slate-200">{drv.used_gb} GB</strong></span>
                        <span>Remaining Free: <strong className="text-emerald-400">{drv.free_gb} GB</strong></span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-5 col-span-3 flex items-center justify-center text-slate-500 text-xs">
                    Select an active node to inspect storage drive allocations.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* 5. Remote Maintenance & Command Console */}
          {isWidgetAllowed('remoteHub') && selectedMachine && (
            <div className="bg-[#131d31] border border-teal-800/40 rounded-xl p-5 shadow-sm space-y-4">
              <div className="flex justify-between items-center border-b border-[#1e293b] pb-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-teal-400" />
                  <h3 className="font-semibold text-white text-sm">
                    Remote Maintenance & Command Console — {selectedMachine.hostname}
                  </h3>
                </div>
                <span className="text-[11px] text-teal-400 font-mono">
                  Active Session: {selectedMachine.logged_in_user} (Elevated)
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="md:col-span-2 flex gap-2">
                  <input
                    type="text"
                    placeholder="Execute PowerShell / Bash command (e.g. ipconfig, whoami, Get-Process)..."
                    value={remoteCommand}
                    onChange={(e) => setRemoteCommand(e.target.value)}
                    className="flex-1 bg-[#0f172a] border border-[#334155] rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-teal-500 font-mono"
                  />
                  <button
                    onClick={() => handleExecuteRemoteAction("EXECUTE_SHELL", { command_str: remoteCommand })}
                    disabled={isExecutingCmd || !remoteCommand.trim() || !hasPerm('remote_ops.execute')}
                    className="bg-teal-600 hover:bg-teal-500 text-white px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition disabled:opacity-50"
                  >
                    <Play className="w-3.5 h-3.5" /> Execute
                  </button>
                </div>

                <div className="flex gap-2 justify-end">
                  <button
                    onClick={() => {
                      if (window.confirm(`⚠️ Reboot remote host "${selectedMachine.hostname}"?`)) {
                        handleExecuteRemoteAction("REBOOT_SYSTEM");
                      }
                    }}
                    disabled={!hasPerm('remote_ops.execute')}
                    className="bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition disabled:opacity-50"
                  >
                    <Power className="w-3.5 h-3.5 text-red-400" /> Remote Reboot
                  </button>
                </div>
              </div>

              {consoleOutput && (
                <div className="bg-[#0b0f19] border border-[#1e293b] rounded-xl p-4 font-mono text-xs text-slate-200">
                  <div className="flex justify-between items-center border-b border-[#1e293b] pb-2 mb-2 text-[11px] text-slate-400">
                    <span>Host Execution Output Stream</span>
                    <button onClick={() => setConsoleOutput('')} className="text-slate-500 hover:text-white">Clear</button>
                  </div>
                  <pre className="whitespace-pre-wrap max-h-48 overflow-y-auto leading-relaxed text-emerald-400">
                    {consoleOutput}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* 5b. System Health — extended telemetry (services / containers / sensors / GPU) */}
          {isWidgetAllowed('systemHealth') && (
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-teal-400" />
                  System Health — {selectedMachine?.hostname || 'No node'}
                </h3>
                <span className="text-[11px] text-slate-400">Extended telemetry</span>
              </div>

              {!extendedMetrics ? (
                <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-5 text-sm text-slate-500">
                  Select a node to view its services, containers, sensors and GPU.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2 text-slate-300 text-xs font-bold"><Layers className="w-4 h-4 text-teal-400" /> Services</div>
                    {extendedMetrics.services ? (
                      <>
                        <p className="text-2xl font-bold text-teal-400 font-mono">{extendedMetrics.services.running ?? (extendedMetrics.services.items?.length || 0)}</p>
                        <p className="text-[11px] text-slate-400">running</p>
                        <div className="max-h-24 overflow-y-auto text-[11px] text-slate-400 space-y-0.5">
                          {(extendedMetrics.services.items || []).slice(0, 8).map((s, i) => (<div key={i} className="truncate">{s.name || s.display_name}</div>))}
                        </div>
                      </>
                    ) : <p className="text-[11px] text-slate-500 italic">Not reported by this host</p>}
                  </div>

                  <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2 text-slate-300 text-xs font-bold"><Server className="w-4 h-4 text-indigo-400" /> Containers</div>
                    {extendedMetrics.containers ? (
                      <>
                        <p className="text-2xl font-bold text-indigo-400 font-mono">{extendedMetrics.containers.count ?? (extendedMetrics.containers.items?.length || 0)}</p>
                        <p className="text-[11px] text-slate-400">running</p>
                        <div className="max-h-24 overflow-y-auto text-[11px] text-slate-400 space-y-0.5">
                          {(extendedMetrics.containers.items || []).slice(0, 8).map((c, i) => (<div key={i} className="truncate">{c.name} <span className="text-slate-600">{c.image}</span></div>))}
                        </div>
                      </>
                    ) : <p className="text-[11px] text-slate-500 italic">Not reported by this host</p>}
                  </div>

                  <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2 text-slate-300 text-xs font-bold"><Activity className="w-4 h-4 text-amber-400" /> Temperature</div>
                    {extendedMetrics.sensors ? (
                      <div className="max-h-32 overflow-y-auto text-[11px] text-slate-300 space-y-1">
                        {Object.entries(extendedMetrics.sensors).flatMap(([chip, arr]) => (arr || []).map((se, i) => (
                          <div key={chip + i} className="flex justify-between gap-2"><span className="truncate">{se.label || chip}</span><span className="font-mono text-amber-400">{se.current}&deg;C</span></div>
                        )))}
                      </div>
                    ) : <p className="text-[11px] text-slate-500 italic">Not reported by this host</p>}
                  </div>

                  <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2 text-slate-300 text-xs font-bold"><Cpu className="w-4 h-4 text-emerald-400" /> GPU</div>
                    {extendedMetrics.gpu ? (
                      <div className="max-h-32 overflow-y-auto text-[11px] text-slate-300 space-y-1">
                        {(extendedMetrics.gpu.items || []).map((g, i) => (
                          <div key={i}><div className="truncate font-bold">{g.name}</div><div className="text-slate-400">util {g.util_percent}% &middot; {g.mem_used_mb}/{g.mem_total_mb} MB &middot; {g.temp_c}&deg;C</div></div>
                        ))}
                      </div>
                    ) : <p className="text-[11px] text-slate-500 italic">Not reported by this host</p>}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 6. Live Process Task Manager */}
          {isWidgetAllowed('taskManager') && (
            <div className="bg-[#131d31] border border-[#1e293b] rounded-xl overflow-hidden shadow-sm">
              <div className="p-4 border-b border-[#1e293b] flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#0f172a]/50">
                <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                  <Layers className="w-4 h-4 text-teal-400" /> Live Process Task Manager — {selectedMachine?.hostname || 'No node'} ({filteredProcesses.length} Running)
                </h3>

                <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
                  <div className="relative flex-1 md:w-64">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Search process name or PID..."
                      value={procSearch}
                      onChange={(e) => setProcSearch(e.target.value)}
                      className="w-full bg-[#131d31] border border-[#334155] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-teal-500"
                    />
                  </div>

                  <select
                    value={procSortKey}
                    onChange={(e) => setProcSortKey(e.target.value)}
                    className="bg-[#131d31] border border-[#334155] text-xs text-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-teal-500"
                  >
                    <option value="cpu">Sort by CPU %</option>
                    <option value="ram">Sort by RAM %</option>
                  </select>

                  <select
                    value={procSortOrder}
                    onChange={(e) => setProcSortOrder(e.target.value)}
                    className="bg-[#131d31] border border-[#334155] text-xs text-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-teal-500"
                  >
                    <option value="desc">⬇️ High to Low</option>
                    <option value="asc">⬆️ Low to High</option>
                  </select>
                </div>
              </div>

              <div className="overflow-x-auto max-h-96 overflow-y-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-[#0f172a] text-xs text-slate-400 uppercase border-b border-[#1e293b] sticky top-0 z-10">
                    <tr>
                      <th className="px-6 py-3">Process Name</th>
                      <th className="px-6 py-3">PID</th>
                      <th className="px-6 py-3">CPU Usage</th>
                      <th className="px-6 py-3">RAM Usage</th>
                      <th className="px-6 py-3">Process State</th>
                      <th className="px-6 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e293b]">
                    {filteredProcesses.map((p, idx) => (
                      <tr key={idx} className="hover:bg-[#1e293b]/60 transition">
                        <td className="px-6 py-3 font-medium text-white">{p.name}</td>
                        <td className="px-6 py-3 font-mono text-xs text-slate-400">{p.pid}</td>
                        <td className="px-6 py-3 font-semibold text-teal-400">{p.cpu_percent}%</td>
                        <td className="px-6 py-3 text-sky-400">{p.memory_percent}%</td>
                        <td className="px-6 py-3">
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300">
                            {p.status}
                          </span>
                        </td>
                        <td className="px-6 py-3 text-right">
                          <button
                            onClick={() => handleKillProcess(p.pid, pname)}
                            disabled={!hasPerm('processes.kill')}
                            className="text-xs bg-red-950/80 hover:bg-red-900 text-red-300 border border-red-800 px-3 py-1 rounded transition inline-flex items-center gap-1.5 disabled:opacity-40"
                          >
                            <Trash2 className="w-3 h-3 text-red-400" /> End Process Tree
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 7. Node Inventory Table WITH VISUAL HIGHLIGHT ON INSPECT */}
          {isWidgetAllowed('nodeInventory') && (
            <div className="bg-[#131d31] border border-[#1e293b] rounded-xl overflow-hidden shadow-sm">
              <div className="p-4 border-b border-[#1e293b] flex justify-between items-center bg-[#0f172a]/50">
                <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                  <Server className="w-4 h-4 text-slate-400" /> Infrastructure Node Inventory ({filteredMachines.length})
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-[#0f172a] text-xs text-slate-400 uppercase border-b border-[#1e293b]">
                    <tr>
                      <th className="px-6 py-3">Hostname & Active User</th>
                      <th className="px-6 py-3">Agent ID</th>
                      <th className="px-6 py-3">OS Platform</th>
                      <th className="px-6 py-3">Physical MAC</th>
                      <th className="px-6 py-3">Health Status</th>
                      <th className="px-6 py-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e293b]">
                    {filteredMachines.map((m) => {
                      const isSelected = selectedMachine && selectedMachine.id === m.id;
                      return (
                        <tr key={m.id} className={`transition ${
                          isSelected ? 'bg-teal-950/40 border-l-4 border-teal-400' : 'hover:bg-[#1e293b]/60'
                        }`}>
                          <td className="px-6 py-3.5 font-medium text-white flex items-center gap-2">
                            {isSelected && <CheckSquare className="w-4 h-4 text-teal-400 animate-pulse" />}
                            <div>
                              {m.hostname}
                              <div className="text-[11px] text-slate-400">User: {m.logged_in_user || 'System'}</div>
                            </div>
                          </td>
                          <td className="px-6 py-3.5 font-mono text-xs text-slate-400">{m.agent_id}</td>
                          <td className="px-6 py-3.5">{m.os_name} ({m.architecture})</td>
                          <td className="px-6 py-3.5 font-mono text-xs text-teal-300">
                            {m.mac_address || <span className="text-slate-500 italic">Not Registered</span>}
                          </td>
                          <td className="px-6 py-3.5">
                            <span className={`px-2.5 py-0.5 rounded text-xs font-semibold ${
                              m.status === 'HEALTHY' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                            }`}>
                              {m.status}
                            </span>
                          </td>
                          <td className="px-6 py-3.5 text-right">
                            <button
                              onClick={() => {
                                setSelectedMachine(m);
                                showToast(`[+] Now Inspecting Node: ${m.hostname}`);
                              }}
                              className={`text-xs px-3.5 py-1.5 rounded-lg border font-semibold transition ${
                                isSelected ? 'bg-teal-600 text-white border-teal-400 shadow-md' : 'bg-teal-950 text-teal-400 border-teal-800 hover:bg-teal-900'
                              }`}
                            >
                              {isSelected ? '✓ Inspecting' : 'Inspect'}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 8. Operational Incidents & AI RCA Diagnostic Table */}
          {isWidgetAllowed('incidentsTable') && (
            <div className="bg-[#131d31] border border-[#1e293b] rounded-xl overflow-hidden shadow-sm">
              <div className="px-6 py-4 border-b border-[#1e293b] flex justify-between items-center">
                <div>
                  <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" /> Operational Incidents & AI RCA Diagnostic ({filteredIncidents.length})
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">Automated telemetry anomalies and AI root cause post-mortem generator</p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setIncidentStatusFilter('ALL')}
                    className={`text-xs px-2.5 py-1 rounded ${incidentStatusFilter === 'ALL' ? 'bg-teal-600 text-white' : 'text-slate-400'}`}
                  >
                    All
                  </button>
                  <button
                    onClick={() => setIncidentStatusFilter('OPEN')}
                    className={`text-xs px-2.5 py-1 rounded ${incidentStatusFilter === 'OPEN' ? 'bg-amber-600 text-white' : 'text-slate-400'}`}
                  >
                    Open
                  </button>
                  <button
                    onClick={() => setIncidentStatusFilter('RESOLVED')}
                    className={`text-xs px-2.5 py-1 rounded ${incidentStatusFilter === 'RESOLVED' ? 'bg-emerald-600 text-white' : 'text-slate-400'}`}
                  >
                    Resolved
                  </button>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-slate-300">
                  <thead className="bg-[#0f172a] text-xs text-slate-400 uppercase border-b border-[#1e293b]">
                    <tr>
                      <th className="px-6 py-3">Code</th>
                      <th className="px-6 py-3">Target Host</th>
                      <th className="px-6 py-3">Status</th>
                      <th className="px-6 py-3">Problem Title</th>
                      <th className="px-6 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e293b]">
                    {filteredIncidents.map((inc) => (
                      <tr key={inc.id} className="hover:bg-[#1e293b]/60 transition">
                        <td className="px-6 py-4 font-mono font-bold text-teal-400 text-xs">{inc.incident_code}</td>
                        <td className="px-6 py-4">{inc.machine_hostname}</td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                            inc.status === 'RESOLVED' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-amber-950 text-amber-400 border-amber-800'
                          }`}>
                            {inc.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-xs">{inc.title}</td>
                        <td className="px-6 py-4 text-right space-x-2">
                          <button 
                            onClick={() => handleAnalyzeWithAI(inc.id)}
                            disabled={!hasPerm('incidents.analyze')}
                            className="text-xs bg-teal-950 hover:bg-teal-900 text-teal-300 border border-teal-700 px-3 py-1 rounded disabled:opacity-40"
                          >
                            AI RCA
                          </button>
                          <button 
                            onClick={() => handleDownloadPDF(inc.id, inc.incident_code)}
                            disabled={!hasPerm('incidents.export')}
                            className="text-xs bg-blue-950 hover:bg-blue-900 text-blue-300 border border-blue-700 px-3 py-1 rounded disabled:opacity-40"
                          >
                            PDF
                          </button>
                          {inc.status !== 'RESOLVED' && hasPerm('incidents.resolve') && (
                            <button 
                              onClick={() => { setResolvingIncident(inc); setResolutionText(''); }}
                              className="text-xs bg-emerald-950 hover:bg-emerald-900 text-emerald-400 border border-emerald-800 px-3 py-1 rounded"
                            >
                              Resolve
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </main>
      )}

      {/* VIEW: ASSET AUDIT / NETWORK DISCOVERY */}
      {activeView === 'ASSETS' && (
        <div className="p-6 space-y-5 max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2"><Radio className="w-5 h-5 text-teal-400" /> Asset Audit &mdash; Network Discovery</h2>
              <p className="text-xs text-slate-400 mt-1">Scan the local network to inventory every connected device &mdash; routers, servers, PCs, VMs and mobiles.</p>
            </div>
            <div className="flex items-center gap-2">
              <input value={scanSubnet} onChange={(e) => setScanSubnet(e.target.value)} placeholder="Auto (e.g. 192.168.1.0/24)" className="bg-[#0f172a] border border-[#334155] text-white text-xs rounded-lg px-3 py-2 w-56 focus:outline-none focus:border-teal-500" />
              <button onClick={runNetworkScan} disabled={isScanning} className="bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-2 whitespace-nowrap">
                {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Radio className="w-4 h-4" />} {isScanning ? 'Scanning...' : 'Scan Network'}
              </button>
              <button onClick={exportCSV} className="bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-2 whitespace-nowrap">
                <FileDown className="w-4 h-4" /> Export CSV
              </button>
            </div>
          </div>

          {scanMsg && <div className="text-xs text-slate-300 bg-[#0f172a] border border-[#1e293b] rounded-lg px-4 py-2">{scanMsg}</div>}

          <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Saved Ranges</h3>
              <div className="flex items-center gap-2">
                <input value={newRangeName} onChange={(e) => setNewRangeName(e.target.value)} placeholder="Name (e.g. Server LAN)" className="bg-[#0f172a] border border-[#334155] text-white text-xs rounded-lg px-3 py-1.5 w-44 focus:outline-none focus:border-teal-500" />
                <button onClick={saveRange} className="bg-slate-700 hover:bg-slate-600 text-white text-xs px-3 py-1.5 rounded-lg whitespace-nowrap">Save current range</button>
              </div>
            </div>
            {savedRanges.length === 0 ? (
              <p className="text-[11px] text-slate-500">No saved ranges yet. Type a range in the box above, give it a name, then click "Save current range".</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {savedRanges.map((r) => (
                  <div key={r.id} className="flex items-center gap-2 bg-[#0f172a] border border-[#1e293b] rounded-lg px-3 py-1.5 text-xs">
                    <button onClick={() => scanRange(r.target)} className="text-teal-400 hover:text-teal-300 font-medium">{r.name}</button>
                    <span className="text-slate-500 font-mono">{r.target}</span>
                    <button onClick={() => deleteRange(r.id)} className="text-rose-400 hover:text-rose-300 font-bold">&times;</button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {[...new Set(networkDevices.map((d) => d.source_subnet).filter(Boolean))].length > 1 && (
            <div className="flex flex-wrap gap-2 items-center">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 mr-1">Range:</span>
              {['ALL', ...new Set(networkDevices.map((d) => d.source_subnet).filter(Boolean))].map((rg) => {
                const cnt = rg === 'ALL' ? networkDevices.length : networkDevices.filter((d) => (d.source_subnet || '') === rg).length;
                return (
                  <button
                    key={rg}
                    onClick={() => setRangeFilter(rg)}
                    className={`text-xs px-3 py-1.5 rounded-lg border transition ${rangeFilter === rg ? 'bg-indigo-600 border-indigo-500 text-white font-semibold' : 'bg-[#131d31] border-[#1e293b] text-slate-400 hover:text-white'}`}
                  >
                    {rg === 'ALL' ? 'All Ranges' : rg} <span className="ml-1 opacity-70">({cnt})</span>
                  </button>
                );
              })}
            </div>
          )}

          <div className="flex flex-wrap gap-2 items-center">
            <span className="text-[10px] uppercase tracking-wider text-slate-500 mr-1">Type:</span>
            {[['ALL', 'All'], ['COMPUTER', 'Computers'], ['MOBILE', 'Mobiles'], ['NETWORK', 'Network'], ['VM', 'VMs'], ['IOT', 'IoT'], ['OTHER', 'Other']].map(([key, label]) => {
              const cnt = key === 'ALL' ? networkDevices.length : networkDevices.filter((d) => catOf(d.device_type) === key).length;
              return (
                <button
                  key={key}
                  onClick={() => setDeviceFilter(key)}
                  className={`text-xs px-3 py-1.5 rounded-lg border transition ${deviceFilter === key ? 'bg-teal-600 border-teal-500 text-white font-semibold' : 'bg-[#131d31] border-[#1e293b] text-slate-400 hover:text-white'}`}
                >
                  {label} <span className="ml-1 opacity-70">({cnt})</span>
                </button>
              );
            })}
          </div>

          <div className="bg-[#131d31] border border-[#1e293b] rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-[#0f172a] text-slate-400 uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="text-left px-4 py-3">St</th>
                    <th className="text-left px-4 py-3">IP Address</th>
                    <th className="text-left px-4 py-3">MAC</th>
                    <th className="text-left px-4 py-3">Vendor</th>
                    <th className="text-left px-4 py-3">Device Type</th>
                    <th className="text-left px-4 py-3">OS</th>
                    <th className="text-left px-4 py-3">Hostname</th>
                    <th className="text-left px-4 py-3">Open Ports / Services</th>
                    <th className="text-left px-4 py-3">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]">
                  {filteredDevices.length === 0 ? (
                    <tr><td colSpan={9} className="px-4 py-8 text-center text-slate-500">{networkDevices.length === 0 ? 'No devices yet. Click "Scan Network" to discover assets on your LAN.' : 'No devices in this category.'}</td></tr>
                  ) : filteredDevices.map((d) => (
                    <tr key={d.id} className="hover:bg-[#0f172a]/40">
                      <td className="px-4 py-2.5"><span className={`inline-block w-2 h-2 rounded-full ${d.is_online ? 'bg-emerald-400' : 'bg-slate-600'}`}></span></td>
                      <td className="px-4 py-2.5 font-mono text-teal-300">{d.ip_address}</td>
                      <td className="px-4 py-2.5 font-mono text-slate-400">{d.mac_address}</td>
                      <td className="px-4 py-2.5 text-slate-300">{d.vendor}</td>
                      <td className="px-4 py-2.5 text-slate-300">{d.device_type}</td>
                      <td className="px-4 py-2.5 text-slate-400">{d.os_guess || '—'}</td>
                      <td className="px-4 py-2.5 text-slate-400">{d.hostname || '—'}</td>
                      <td className="px-4 py-2.5 text-slate-400 font-mono text-[10px] max-w-xs truncate" title={d.open_ports || ''}>{d.open_ports || '—'}</td>
                      <td className="px-4 py-2.5 text-slate-500">{d.last_seen ? new Date(d.last_seen).toLocaleString() : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeView === 'INV_ASSETS' && (
        <div className="px-6 pt-5 max-w-full mx-auto flex items-center gap-2 flex-wrap">
          <span className="text-[10px] uppercase tracking-wider text-slate-500 mr-1">Show:</span>
          {[['BOTH', 'Both'], ['INVENTORY', 'Inventory'], ['REGISTER', 'Asset Register']].map(([k, l]) => (
            <button key={k} onClick={() => setInvAssetTab(k)} className={`text-xs px-4 py-1.5 rounded-lg border transition ${invAssetTab === k ? 'bg-teal-600 border-teal-500 text-white font-semibold' : 'bg-[#131d31] border-[#1e293b] text-slate-400 hover:text-white'}`}>{l}</button>
          ))}
        </div>
      )}

      {/* VIEW: INVENTORY (OCS-style hardware + software) */}
      {activeView === 'INV_ASSETS' && (invAssetTab === 'INVENTORY' || invAssetTab === 'BOTH') && (
        <div className="p-6 space-y-5 max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2"><HardDrive className="w-5 h-5 text-teal-400" /> Machine Inventory</h2>
              <p className="text-xs text-slate-400 mt-1">Detailed hardware and the full installed-software list for each agent, plus a fleet-wide software search.</p>
            </div>
            <a href={`${API_BASE}/agents/download`} className="bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-2 whitespace-nowrap self-start">
              <FileDown className="w-4 h-4" /> Download Agent (install on a machine for full details)
            </a>
          </div>

          {/* global software search */}
          <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Fleet Software Search</h3>
            <div className="flex items-center gap-2">
              <input value={softwareQuery} onChange={(e) => setSoftwareQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && searchSoftware()} placeholder="Find which machines have a package, e.g. nginx, python3, chrome" className="flex-1 bg-[#0f172a] border border-[#334155] text-white text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-teal-500" />
              <button onClick={searchSoftware} className="bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-2"><Search className="w-4 h-4" /> Search</button>
            </div>
            {softwareResults.length > 0 && (
              <div className="max-h-56 overflow-y-auto border border-[#1e293b] rounded-lg">
                <table className="w-full text-xs">
                  <thead className="bg-[#0f172a] text-slate-400 uppercase text-[10px]"><tr><th className="text-left px-3 py-2">Machine</th><th className="text-left px-3 py-2">Package</th><th className="text-left px-3 py-2">Version</th></tr></thead>
                  <tbody className="divide-y divide-[#1e293b]">
                    {softwareResults.map((r, i) => (
                      <tr key={i}><td className="px-3 py-1.5 text-teal-300">{r.hostname}</td><td className="px-3 py-1.5 text-slate-300">{r.name}</td><td className="px-3 py-1.5 font-mono text-slate-400">{r.version}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* per-machine inventory */}
          <div className="flex items-center gap-3">
            <label className="text-xs text-slate-400">Machine:</label>
            <select value={invMachineId} onChange={(e) => { setInvMachineId(e.target.value); fetchInventory(e.target.value); }} className="bg-[#0f172a] border border-[#334155] text-white text-xs rounded-lg px-3 py-2 w-72">
              <option value="">Select a machine...</option>
              {machines.map((m) => (<option key={m.id} value={m.id}>{m.hostname}</option>))}
            </select>
          </div>

          {inventory && inventory.hardware ? (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 space-y-2 lg:col-span-1">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Hardware</h3>
                {[['CPU', inventory.hardware.cpu_model], ['Cores', `${inventory.hardware.cpu_cores_physical || '?'} physical / ${inventory.hardware.cpu_cores_logical || '?'} logical`], ['RAM', `${inventory.hardware.ram_total_gb} GB`], ['OS', inventory.hardware.os_pretty], ['Kernel', inventory.hardware.kernel], ['Arch', inventory.hardware.arch], ['Manufacturer', inventory.hardware.manufacturer], ['Model', inventory.hardware.product], ['Serial No', inventory.hardware.serial], ['BIOS', inventory.hardware.bios_version], ['OS Edition', inventory.hardware.os_edition]].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3 text-xs border-b border-[#1e293b]/60 pb-1"><span className="text-slate-500">{k}</span><span className="text-slate-200 text-right truncate" title={v || ''}>{v || '\u2014'}</span></div>
                ))}
                <div className="pt-2">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Disks</p>
                  {(inventory.hardware.disks || []).map((d, i) => (<div key={i} className="text-[11px] text-slate-300 font-mono">{d.mount} — {d.total_gb} GB ({d.fstype})</div>))}
                </div>
                <div className="pt-2">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Network Adapters</p>
                  {(inventory.hardware.network_adapters || []).map((n, i) => (<div key={i} className="text-[11px] text-slate-300 font-mono">{n.name} {n.mac ? `[${n.mac}]` : ''} {(n.ipv4 || []).join(', ')}</div>))}
                </div>
              </div>

              <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4 lg:col-span-2 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Installed Software ({inventory.software_count})</h3>
                  <input value={swFilter} onChange={(e) => setSwFilter(e.target.value)} placeholder="Filter..." className="bg-[#0f172a] border border-[#334155] text-white text-xs rounded-lg px-3 py-1.5 w-48" />
                </div>
                <div className="max-h-96 overflow-y-auto border border-[#1e293b] rounded-lg">
                  <table className="w-full text-xs">
                    <thead className="bg-[#0f172a] text-slate-400 uppercase text-[10px] sticky top-0"><tr><th className="text-left px-3 py-2">Package</th><th className="text-left px-3 py-2">Version</th></tr></thead>
                    <tbody className="divide-y divide-[#1e293b]">
                      {(inventory.software || []).filter((sw) => !swFilter || (sw.name || '').toLowerCase().includes(swFilter.toLowerCase())).slice(0, 800).map((sw, i) => (
                        <tr key={i}><td className="px-3 py-1 text-slate-300">{sw.name}</td><td className="px-3 py-1 font-mono text-slate-400">{sw.version}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-[#131d31] border border-[#1e293b] rounded-xl p-6 text-center text-slate-500 text-sm">
              {invMachineId ? 'No inventory reported yet for this machine. The agent sends it within a few minutes of starting.' : 'Select a machine to see its hardware and installed software.'}
            </div>
          )}
        </div>
      )}

      {/* VIEW: ASSET REGISTER (Excel-style) */}
      {activeView === 'INV_ASSETS' && (invAssetTab === 'REGISTER' || invAssetTab === 'BOTH') && (
        <div className="p-6 space-y-5 max-w-full mx-auto">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2"><FileText className="w-5 h-5 text-teal-400" /> Asset Register</h2>
              <p className="text-xs text-slate-400 mt-1">Full asset inventory. Technical columns auto-fill from agents; fill the rest and export to Excel/CSV.</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={syncAssets} className="bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Sync from Agents</button>
              <button onClick={() => setAssetModal({})} className="bg-teal-600 hover:bg-teal-500 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-2"><UserPlus className="w-4 h-4" /> Add Asset</button>
              <button onClick={exportAssets} className="bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-2"><FileDown className="w-4 h-4" /> Export CSV</button>
            </div>
          </div>

          {assetCoverage && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[['Network Devices', assetCoverage.network_devices, 'text-cyan-400'],
                ['Registered Assets', assetCoverage.registered_assets, 'text-teal-400'],
                ['Matched', assetCoverage.matched, 'text-emerald-400'],
                ['Not Registered', assetCoverage.unregistered_count, 'text-amber-400']].map(([label, val, cls]) => (
                <div key={label} className="bg-[#131d31] border border-[#1e293b] rounded-xl p-4">
                  <p className={`text-2xl font-bold font-mono ${cls}`}>{val}</p>
                  <p className="text-[11px] text-slate-400 uppercase tracking-wider">{label}</p>
                </div>
              ))}
            </div>
          )}

          <div className="bg-[#131d31] border border-[#1e293b] rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="text-xs whitespace-nowrap">
                <thead className="bg-[#0f172a] text-slate-400 uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="text-left px-3 py-3 sticky left-0 bg-[#0f172a]">#</th>
                    {ASSET_COLS.map(([k, label]) => (<th key={k} className="text-left px-3 py-3">{label}</th>))}
                    <th className="text-left px-3 py-3">Edit</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]">
                  {assets.length === 0 ? (
                    <tr><td colSpan={ASSET_COLS.length + 2} className="px-4 py-8 text-center text-slate-500">No assets yet. Click "Sync from Agents" to auto-fill from reporting machines, or "Add Asset".</td></tr>
                  ) : assets.map((a, idx) => (
                    <tr key={a.id} className="hover:bg-[#0f172a]/40">
                      <td className="px-3 py-2 text-slate-500 sticky left-0 bg-[#131d31]">{idx + 1}</td>
                      {ASSET_COLS.map(([k]) => (<td key={k} className="px-3 py-2 text-slate-300">{a[k] || '\u2014'}</td>))}
                      <td className="px-3 py-2"><button onClick={() => setAssetModal({ ...a })} className="text-teal-400 hover:text-teal-300"><Sliders className="w-3.5 h-3.5" /></button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {assetCoverage && assetCoverage.unregistered_count > 0 && (
            <div className="bg-[#131d31] border border-amber-800/40 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-400">On the network but NOT in the register ({assetCoverage.unregistered_count})</h3>
                <div className="flex flex-wrap gap-1.5">
                  {[['ALL', 'All'], ['COMPUTER', 'Computers'], ['MOBILE', 'Mobiles'], ['NETWORK', 'Network'], ['VM', 'VMs'], ['OTHER', 'Other']].map(([k, l]) => {
                    const cnt = k === 'ALL' ? assetCoverage.unregistered.length : assetCoverage.unregistered.filter((d) => catOf(d.device_type) === k).length;
                    return (
                      <button key={k} onClick={() => setUnregFilter(k)} className={`text-[11px] px-2.5 py-1 rounded border transition ${unregFilter === k ? 'bg-amber-600 border-amber-500 text-white font-semibold' : 'bg-[#0f172a] border-[#1e293b] text-slate-400 hover:text-white'}`}>{l} ({cnt})</button>
                    );
                  })}
                </div>
              </div>
              <p className="text-[11px] text-slate-500">Devices worth adding as assets (computers, servers) are marked <span className="text-emerald-300">Recommended</span> and shown first. Click <span className="text-teal-300">+ Add</span> to register one.</p>
              <div className="max-h-72 overflow-y-auto">
                <table className="w-full text-[11px]">
                  <thead className="text-slate-500 uppercase text-[10px] sticky top-0 bg-[#131d31]"><tr><th className="text-left py-1 pr-2"> </th><th className="text-left py-1 pr-2">IP</th><th className="text-left py-1 pr-2">Hostname</th><th className="text-left py-1 pr-2">MAC</th><th className="text-left py-1 pr-2">Type</th><th className="text-left py-1">Add</th></tr></thead>
                  <tbody>
                    {assetCoverage.unregistered
                      .filter((d) => unregFilter === 'ALL' || catOf(d.device_type) === unregFilter)
                      .slice()
                      .sort((a, b) => importanceRank(a.device_type) - importanceRank(b.device_type))
                      .slice(0, 200)
                      .map((d, i) => {
                        const rec = importanceRank(d.device_type) <= 1;
                        return (
                          <tr key={i} className="hover:bg-[#0f172a]/40">
                            <td className="py-1 pr-2">{rec && <span className="text-[9px] bg-emerald-900/60 text-emerald-300 border border-emerald-700 px-1.5 py-0.5 rounded whitespace-nowrap">Recommended</span>}</td>
                            <td className="py-1 pr-2 font-mono text-cyan-300">{d.ip}</td>
                            <td className="py-1 pr-2 text-slate-300">{d.hostname || '\u2014'}</td>
                            <td className="py-1 pr-2 font-mono text-slate-500">{d.mac || '\u2014'}</td>
                            <td className="py-1 pr-2 text-slate-400">{d.device_type}</td>
                            <td className="py-1"><button onClick={() => setAssetModal({ host_name: d.hostname || d.ip })} className="text-teal-400 hover:text-teal-300 font-semibold">+ Add</button></td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {assetModal !== null && (
            <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
              <div className="bg-[#0e1424] border border-slate-800 rounded-xl max-w-3xl w-full p-5 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
                <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-bold text-white">{assetModal.id ? 'Edit Asset' : 'Add Asset'}</h3>
                  <button onClick={() => setAssetModal(null)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {ASSET_COLS.map(([k, label]) => (
                    <div key={k}>
                      <label className="block text-[10px] uppercase tracking-wider text-slate-400 mb-1">{label}</label>
                      <input
                        type={k.startsWith('warranty') ? 'date' : 'text'}
                        value={assetModal[k] || ''}
                        onChange={(e) => setAssetModal({ ...assetModal, [k]: e.target.value })}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-teal-500"
                      />
                    </div>
                  ))}
                </div>
                <div className="flex justify-between pt-3 border-t border-slate-800">
                  {assetModal.id ? (
                    <button onClick={() => { deleteAsset(assetModal.id); setAssetModal(null); }} className="text-rose-400 hover:text-rose-300 text-xs">Delete</button>
                  ) : <span />}
                  <div className="flex gap-2">
                    <button onClick={() => setAssetModal(null)} className="bg-slate-800 text-slate-300 px-4 py-1.5 rounded text-xs">Cancel</button>
                    <button onClick={saveAsset} className="bg-teal-600 hover:bg-teal-500 text-white font-bold px-4 py-1.5 rounded text-xs">Save</button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: MAIN ADMIN CONSOLE */}
      {activeView === 'ADMIN_CONSOLE' && hasPerm('admin.users_manage') && (
        <main className="p-6 flex-1 space-y-6 max-w-7xl mx-auto w-full mb-16">
          <div className="flex justify-between items-center bg-[#131d31] p-5 rounded-2xl border border-[#1e293b]">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-teal-400" /> Main Administration Console
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">Centralized User Access Management, Widget Granular Permissions & Security Audit Stream</p>
            </div>
            <button
              onClick={handleOpenCreateUser}
              className="bg-teal-600 hover:bg-teal-500 text-white px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition"
            >
              <UserPlus className="w-4 h-4" /> Create New User
            </button>
          </div>

          {/* User Management Table */}
          <div className="bg-[#131d31] border border-[#1e293b] rounded-2xl overflow-hidden">
            <div className="p-4 border-b border-[#1e293b] bg-[#0f172a]/50">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <Users className="w-4 h-4 text-teal-400" /> Corporate Users & Granted Permissions ({usersList.length})
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-[#0f172a] text-xs text-slate-400 uppercase border-b border-[#1e293b]">
                  <tr>
                    <th className="px-6 py-3">User & Email</th>
                    <th className="px-6 py-3">Role</th>
                    <th className="px-6 py-3">Status</th>
                    <th className="px-6 py-3">Active Widgets Allowed</th>
                    <th className="px-6 py-3">Last Login</th>
                    <th className="px-6 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]">
                  {usersList.map((u) => {
                    const allowedCount = Object.values(u.widget_permissions || {}).filter(Boolean).length;
                    return (
                      <tr key={u.id} className="hover:bg-[#1e293b]/60 transition">
                        <td className="px-6 py-3.5">
                          <div className="font-medium text-white">{u.full_name || 'System User'}</div>
                          <div className="text-xs text-slate-400 font-mono">{u.email}</div>
                        </td>
                        <td className="px-6 py-3.5">
                          <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-teal-950 text-teal-400 border border-teal-800">
                            {u.role}
                          </span>
                        </td>
                        <td className="px-6 py-3.5">
                          <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                            u.is_active ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                          }`}>
                            {u.is_active ? 'ACTIVE' : 'DISABLED'}
                          </span>
                        </td>
                        <td className="px-6 py-3.5 text-xs text-slate-300">
                          {allowedCount} of 8 Widgets Visible
                        </td>
                        <td className="px-6 py-3.5 text-xs text-slate-400">
                          {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                        </td>
                        <td className="px-6 py-3.5 text-right space-x-2">
                          <button
                            onClick={() => handleOpenEditUser(u)}
                            className="text-xs bg-[#1e293b] hover:bg-[#334155] text-slate-200 px-3 py-1.5 rounded transition border border-[#374151]"
                          >
                            Edit Permissions & Widgets
                          </button>
                          <button
                            onClick={() => handleToggleUserActive(u)}
                            className={`text-xs px-2.5 py-1.5 rounded transition border ${
                              u.is_active ? 'bg-red-950 text-red-400 border-red-800' : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                            }`}
                          >
                            {u.is_active ? 'Disable' : 'Enable'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Security Audit Log Stream */}
          <div className="bg-[#131d31] border border-[#1e293b] rounded-2xl overflow-hidden">
            <div className="p-4 border-b border-[#1e293b] bg-[#0f172a]/50">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <FileText className="w-4 h-4 text-teal-400" /> Real-Time Security Audit Stream (Latest 100 Events)
              </h3>
            </div>
            <div className="overflow-x-auto max-h-80 overflow-y-auto">
              <table className="w-full text-left text-xs text-slate-300 font-mono">
                <thead className="bg-[#0b0f19] text-slate-400 uppercase border-b border-[#1e293b] sticky top-0">
                  <tr>
                    <th className="px-6 py-2.5">Timestamp</th>
                    <th className="px-6 py-2.5">Actor</th>
                    <th className="px-6 py-2.5">Security Action</th>
                    <th className="px-6 py-2.5">Target</th>
                    <th className="px-6 py-2.5">Result</th>
                    <th className="px-6 py-2.5">IP Address</th>
                  </tr>
               </thead>
                <tbody className="divide-y divide-[#1e293b]">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-[#1e293b]/40 transition">
                      <td className="px-6 py-2 text-slate-400">{log.timestamp}</td>
                      <td className="px-6 py-2 text-teal-300 font-semibold">{log.actor}</td>
                      <td className="px-6 py-2 text-white">{log.action}</td>
                      <td className="px-6 py-2 text-slate-300">{log.target || '-'}</td>
                      <td className="px-6 py-2">
                        <span className={`px-1.5 py-0.5 rounded ${log.result === 'SUCCESS' ? 'text-emerald-400 bg-emerald-950' : 'text-red-400 bg-red-950'}`}>
                          {log.result}
                        </span>
                      </td>
                      <td className="px-6 py-2 text-slate-400">{log.ip}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </main>
      )}

      {/* FLOATING AI SRE ASSISTANT CHAT */}
      {hasPerm('ai_chat.use') && (
        <>
          <button
            onClick={() => setIsChatOpen(!isChatOpen)}
            className="fixed bottom-6 right-6 bg-teal-600 hover:bg-teal-500 text-white p-3.5 rounded-full shadow-2xl flex items-center gap-2 transition z-40 border border-teal-400/40"
          >
            <Sparkles className="w-5 h-5 text-amber-300" />
            <span className="text-xs font-semibold">AI SRE Assistant</span>
          </button>

          {isChatOpen && (
            <div className="fixed bottom-20 right-6 w-96 bg-[#131d31] border border-teal-500/40 rounded-2xl shadow-2xl z-50 flex flex-col overflow-hidden max-h-[500px]">
              <div className="p-3.5 bg-[#0f172a] border-b border-[#1e293b] flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Bot className="w-4 h-4 text-teal-400" />
                  <span className="text-xs font-bold text-white">AI Diagnostic SRE Copilot</span>
                </div>
                <button onClick={() => setIsChatOpen(false)} className="text-slate-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-4 flex-1 overflow-y-auto space-y-3 text-xs">
                {chatMessages.map((msg, i) => (
                  <div key={i} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`p-2.5 rounded-xl max-w-[85%] leading-relaxed ${
                      msg.sender === 'user' ? 'bg-teal-600 text-white' : 'bg-[#0f172a] text-slate-200 border border-[#1e293b]'
                    }`}>
                      {msg.text}
                    </div>
                  </div>
                ))}
                {chatLoading && <div className="text-xs text-teal-400 animate-pulse">AI is analyzing context...</div>}
                <div ref={chatEndRef} />
              </div>

              <form onSubmit={handleSendChatMessage} className="p-3 border-t border-[#1e293b] bg-[#0f172a] flex gap-2">
                <input
                  type="text"
                  placeholder="Ask troubleshooting question..."
                  value={inputMsg}
                  onChange={(e) => setInputMsg(e.target.value)}
                  className="flex-1 bg-[#131d31] border border-[#334155] rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500"
                />
                <button type="submit" className="bg-teal-600 hover:bg-teal-500 text-white p-2 rounded-lg">
                  <Send className="w-3.5 h-3.5" />
                </button>
              </form>
            </div>
          )}
        </>
      )}

      {/* RESOLVE INCIDENT MODAL */}
      {resolvingIncident && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#131d31] border border-emerald-500/40 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex justify-between items-center border-b border-[#1e293b] pb-3">
              <h3 className="font-bold text-white text-base">Resolve Incident {resolvingIncident.incident_code}</h3>
              <button onClick={() => setResolvingIncident(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <textarea
              rows={3}
              value={resolutionText}
              onChange={(e) => setResolutionText(e.target.value)}
              placeholder="Resolution note for security audit log..."
              className="w-full bg-[#0f172a] border border-[#334155] rounded-xl p-3 text-xs text-white"
            />
            <div className="flex justify-end gap-2">
              <button onClick={() => setResolvingIncident(null)} className="px-3 py-1.5 bg-[#1e293b] text-slate-300 rounded text-xs">Cancel</button>
              <button onClick={handleConfirmResolve} className="px-3 py-1.5 bg-emerald-600 text-white rounded text-xs font-semibold">Confirm</button>
            </div>
          </div>
        </div>
      )}

      {/* USER PERMISSIONS & WIDGET CONFIGURATION MODAL */}
      {isAdminUserModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#131d31] border border-teal-500/40 rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center border-b border-[#1e293b] pb-3">
              <div className="flex items-center gap-2">
                <Sliders className="w-5 h-5 text-teal-400" />
                <h3 className="font-bold text-white text-base">
                  {editingUserId ? "Edit User Permissions & Widgets" : "Create New Corporate User"}
                </h3>
              </div>
              <button onClick={() => setIsAdminUserModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveUser} className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Corporate Email</label>
                  <input
                    type="email"
                    required
                    disabled={!!editingUserId}
                    value={userFormData.email}
                    onChange={(e) => setUserFormData({ ...userFormData, email: e.target.value })}
                    className="w-full bg-[#0f172a] border border-[#334155] rounded-lg p-2 text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Full Name</label>
                  <input
                    type="text"
                    required
                    value={userFormData.full_name}
                    onChange={(e) => setUserFormData({ ...userFormData, full_name: e.target.value })}
                    className="w-full bg-[#0f172a] border border-[#334155] rounded-lg p-2 text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">
                    {editingUserId ? "Reset Password (Leave blank to keep current)" : "Password"}
                  </label>
                  <input
                    type="password"
                    required={!editingUserId}
                    value={userFormData.password}
                    onChange={(e) => setUserFormData({ ...userFormData, password: e.target.value })}
                    className="w-full bg-[#0f172a] border border-[#334155] rounded-lg p-2 text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-semibold mb-1">Role</label>
                  <select
                    value={userFormData.role}
                    onChange={(e) => setUserFormData({ ...userFormData, role: e.target.value })}
                    className="w-full bg-[#0f172a] border border-[#334155] rounded-lg p-2 text-white"
                  >
                    <option value="ADMIN">ADMIN (Full Control)</option>
                    <option value="MANAGER">MANAGER (Incidents & Analytics)</option>
                    <option value="OPERATOR">OPERATOR (Monitoring, WOL & Remote Ops)</option>
                    <option value="VIEWER">VIEWER (Read-Only)</option>
                  </select>
                </div>
              </div>

              {/* Granular Dashboard Widget Assignment */}
              <div className="pt-2 border-t border-[#1e293b]">
                <h4 className="font-bold text-teal-400 uppercase tracking-wider mb-2">
                  Customize Dashboard Widgets Access for this User
                </h4>
                <div className="space-y-2 bg-[#0f172a] p-3 rounded-xl border border-[#1e293b]">
                  {Object.entries(WIDGET_LABELS).map(([wKey, wTitle]) => {
                    const isChecked = userFormData.widget_permissions?.[wKey] !== false;
                    return (
                      <label key={wKey} className="flex items-center justify-between cursor-pointer py-1 border-b border-[#1e293b]/40 last:border-none">
                        <span className="text-slate-200">{wTitle}</span>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={(e) => {
                            setUserFormData({
                              ...userFormData,
                              widget_permissions: {
                                ...userFormData.widget_permissions,
                                [wKey]: e.target.checked
                              }
                            });
                          }}
                          className="w-4 h-4 text-teal-500 rounded border-[#334155]"
                        />
                      </label>
                    );
                  })}
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-[#1e293b]">
                <button
                  type="button"
                  onClick={() => setIsAdminUserModalOpen(false)}
                  className="px-4 py-2 bg-[#1e293b] text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-teal-600 hover:bg-teal-500 text-white rounded-lg font-semibold"
                >
                  {editingUserId ? "Save Changes" : "Create User"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
