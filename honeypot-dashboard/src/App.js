import React, { useState, useEffect } from 'react';
import { MapPin, Activity, Shield, Settings, Clock, Terminal, Globe, PieChart, Save, Play, Square, RefreshCw } from 'lucide-react';

const API_BASE = 'http://localhost:6000/api';

// Dashboard Page Component
const Dashboard = () => {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({});
  const [selectedAttack, setSelectedAttack] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [logsRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/logs`),
        fetch(`${API_BASE}/stats`)
      ]);
      const logsData = await logsRes.json();
      const statsData = await statsRes.json();
      setLogs(logsData);
      setStats(statsData);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setLoading(false);
    }
  };

  const getLocationMarkers = () => {
    const markers = {};
    logs.forEach(log => {
      if (log.ip && log.location) {
        if (!markers[log.ip]) {
          markers[log.ip] = { ...log.location, count: 0, ip: log.ip };
        }
        markers[log.ip].count++;
      }
    });
    return Object.values(markers);
  };

  const getProtocolData = () => {
    const protocols = stats.protocolCounts || {};
    return Object.entries(protocols).map(([name, value]) => ({
      name,
      value,
      color: getProtocolColor(name)
    }));
  };

  const getProtocolColor = (protocol) => {
    const colors = {
      telnet: '#D4A574',
      ssh: '#B8956A',
      http: '#9C8560',
      mqtt: '#807556',
      dnp3: '#64654C',
      coap: '#C4B5A0',
      modbus: '#AFA090'
    };
    return colors[protocol.toLowerCase()] || '#8B8B8B';
  };

  const renderDonutChart = () => {
    const data = getProtocolData();
    const total = data.reduce((sum, d) => sum + d.value, 0);
    let currentAngle = 0;

    return (
      <svg viewBox="0 0 200 200" className="w-full h-full">
        <circle cx="100" cy="100" r="80" fill="none" stroke="#F5F5F0" strokeWidth="40"/>
        {data.map((item, i) => {
          const percentage = item.value / total;
          const angle = percentage * 360;
          const startAngle = currentAngle;
          currentAngle += angle;
          
          const x1 = 100 + 60 * Math.cos((startAngle - 90) * Math.PI / 180);
          const y1 = 100 + 60 * Math.sin((startAngle - 90) * Math.PI / 180);
          const x2 = 100 + 60 * Math.cos((currentAngle - 90) * Math.PI / 180);
          const y2 = 100 + 60 * Math.sin((currentAngle - 90) * Math.PI / 180);
          const largeArc = angle > 180 ? 1 : 0;

          return (
            <path
              key={i}
              d={`M 100 100 L ${x1} ${y1} A 60 60 0 ${largeArc} 1 ${x2} ${y2} Z`}
              fill={item.color}
              opacity="0.9"
            />
          );
        })}
        <circle cx="100" cy="100" r="40" fill="white"/>
        <text x="100" y="105" textAnchor="middle" className="text-2xl font-semibold fill-gray-700">{total}</text>
      </svg>
    );
  };

  const renderWorldMap = () => {
    const markers = getLocationMarkers();
    
    return (
      <div className="relative w-full h-full bg-gray-50 rounded-lg overflow-hidden">
        <svg viewBox="0 0 800 400" className="w-full h-full">
          {/* Simplified world map outline */}
          <path d="M50,200 Q200,150 400,200 T750,200" stroke="#D4A574" strokeWidth="2" fill="none" opacity="0.3"/>
          <path d="M50,250 Q200,220 400,250 T750,250" stroke="#D4A574" strokeWidth="2" fill="none" opacity="0.3"/>
          
          {/* Plot markers based on lat/long */}
          {markers.map((marker, i) => {
            const x = ((marker.lon + 180) / 360) * 800;
            const y = ((90 - marker.lat) / 180) * 400;
            
            return (
              <g key={i}>
                <circle
                  cx={x}
                  cy={y}
                  r={Math.min(marker.count * 2 + 5, 20)}
                  fill="#D4A574"
                  opacity="0.6"
                />
                <circle cx={x} cy={y} r="3" fill="#8B6F47"/>
                <title>{`${marker.ip}: ${marker.count} attacks`}</title>
              </g>
            );
          })}
        </svg>
        <div className="absolute bottom-2 left-2 text-xs text-gray-500">
          <Globe className="w-4 h-4 inline mr-1"/>
          Attack Origin Map
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <RefreshCw className="w-8 h-8 animate-spin text-gray-400"/>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Attacks</p>
              <p className="text-2xl font-semibold text-gray-800">{stats.totalAttacks || 0}</p>
            </div>
            <Shield className="w-8 h-8 text-gray-400"/>
          </div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Unique IPs</p>
              <p className="text-2xl font-semibold text-gray-800">{stats.uniqueIPs || 0}</p>
            </div>
            <MapPin className="w-8 h-8 text-gray-400"/>
          </div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Active Honeypots</p>
              <p className="text-2xl font-semibold text-gray-800">{stats.activeHoneypots || 0}</p>
            </div>
            <Activity className="w-8 h-8 text-gray-400"/>
          </div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Commands Logged</p>
              <p className="text-2xl font-semibold text-gray-800">{stats.commandsLogged || 0}</p>
            </div>
            <Terminal className="w-8 h-8 text-gray-400"/>
          </div>
        </div>
      </div>

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* World Map */}
        <div className="lg:col-span-2 bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
            <Globe className="w-5 h-5 mr-2 text-gray-600"/>
            Attack Origin Map
          </h3>
          <div className="h-80">
            {renderWorldMap()}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
            <PieChart className="w-5 h-5 mr-2 text-gray-600"/>
            Protocol Distribution
          </h3>
          <div className="h-80 flex items-center justify-center">
            {renderDonutChart()}
          </div>
          <div className="mt-4 space-y-2">
            {getProtocolData().map((item, i) => (
              <div key={i} className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full mr-2" style={{backgroundColor: item.color}}/>
                  <span className="text-gray-700 capitalize">{item.name}</span>
                </div>
                <span className="text-gray-600 font-medium">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Timeline */}
      <div className="bg-white p-6 rounded-lg border border-gray-200">
        <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
          <Clock className="w-5 h-5 mr-2 text-gray-600"/>
          Attack Timeline
        </h3>
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {logs.slice(0, 50).map((log, i) => (
            <div
              key={i}
              onClick={() => setSelectedAttack(log)}
              className="flex items-center justify-between p-3 hover:bg-gray-50 rounded cursor-pointer border border-gray-100"
            >
              <div className="flex items-center space-x-4">
                <div className="text-xs text-gray-500 w-32">
                  {new Date(log.timestamp).toLocaleString()}
                </div>
                <div className="flex items-center space-x-2">
                  <MapPin className="w-4 h-4 text-gray-400"/>
                  <span className="text-sm font-mono text-gray-700">{log.ip}</span>
                </div>
                <span className="text-xs px-2 py-1 rounded bg-gray-100 text-gray-600 capitalize">
                  {log.protocol}
                </span>
                <span className="text-sm text-gray-600">{log.type}</span>
              </div>
              <Terminal className="w-4 h-4 text-gray-400"/>
            </div>
          ))}
        </div>
      </div>

      {/* Attack Details Modal */}
      {selectedAttack && (
        <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center p-4 z-50" onClick={() => setSelectedAttack(null)}>
          <div className="bg-white rounded-lg p-6 max-w-3xl w-full max-h-96 overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-xl font-semibold text-gray-800">Attack Details</h3>
                <p className="text-sm text-gray-500 mt-1">{selectedAttack.ip} - {new Date(selectedAttack.timestamp).toLocaleString()}</p>
              </div>
              <button onClick={() => setSelectedAttack(null)} className="text-gray-400 hover:text-gray-600">×</button>
            </div>
            <div className="bg-gray-900 text-gray-100 p-4 rounded font-mono text-sm">
              <div className="mb-2">
                <span className="text-gray-400">Type:</span> {selectedAttack.type}
              </div>
              <div className="mb-2">
                <span className="text-gray-400">Protocol:</span> {selectedAttack.protocol}
              </div>
              {selectedAttack.data && (
                <div>
                  <span className="text-gray-400">Data:</span>
                  <pre className="mt-2 text-xs whitespace-pre-wrap">{JSON.stringify(selectedAttack.data, null, 2)}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Settings Page Component
const SettingsPage = () => {
  const [configs, setConfigs] = useState({});
  const [selectedProtocol, setSelectedProtocol] = useState('telnet');
  const [honeypotStatus, setHoneypotStatus] = useState({});
  const [saving, setSaving] = useState(false);

  const protocols = ['telnet', 'ssh', 'http', 'mqtt', 'dnp3', 'coap', 'modbus'];

  useEffect(() => {
    fetchConfigs();
    fetchHoneypotStatus();
  }, []);

  const fetchConfigs = async () => {
    try {
      const response = await fetch(`${API_BASE}/configs`);
      const data = await response.json();
      setConfigs(data);
    } catch (error) {
      console.error('Error fetching configs:', error);
    }
  };

  const fetchHoneypotStatus = async () => {
    try {
      const response = await fetch(`${API_BASE}/status`);
      const data = await response.json();
      setHoneypotStatus(data);
    } catch (error) {
      console.error('Error fetching status:', error);
    }
  };

  const handleConfigChange = (field, value) => {
    setConfigs(prev => ({
      ...prev,
      [selectedProtocol]: {
        ...prev[selectedProtocol],
        [field]: value
      }
    }));
  };



  const saveConfig = async () => {
    setSaving(true);
    try {
      await fetch(`${API_BASE}/configs/${selectedProtocol}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configs[selectedProtocol])
      });
      alert('Configuration saved successfully!');
    } catch (error) {
      console.error('Error saving config:', error);
      alert('Error saving configuration');
    }
    setSaving(false);
  };

  const toggleHoneypot = async (protocol) => {
    try {
      const action = honeypotStatus[protocol] ? 'stop' : 'start';
      await fetch(`${API_BASE}/honeypot/${protocol}/${action}`, { method: 'POST' });
      fetchHoneypotStatus();
    } catch (error) {
      console.error('Error toggling honeypot:', error);
    }
  };

  const currentConfig = configs[selectedProtocol] || {};

  return (
    <div className="space-y-6">
      <div className="bg-white p-6 rounded-lg border border-gray-200">
        <h2 className="text-2xl font-semibold text-gray-800 mb-6">Honeypot Settings</h2>
        
        {/* Protocol Selection */}
        <div className="mb-6">
          <h3 className="text-sm font-medium text-gray-700 mb-3">Select Protocol</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {protocols.map(protocol => (
              <button
                key={protocol}
                onClick={() => setSelectedProtocol(protocol)}
                className={`p-3 rounded-lg border-2 transition-all capitalize ${
                  selectedProtocol === protocol
                    ? 'border-gray-400 bg-gray-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">{protocol}</span>
                  <div className={`w-2 h-2 rounded-full ${honeypotStatus[protocol] ? 'bg-green-500' : 'bg-gray-300'}`}/>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleHoneypot(protocol);
                  }}
                  className={`w-full py-1 px-2 rounded text-xs ${
                    honeypotStatus[protocol]
                      ? 'bg-red-100 text-red-700 hover:bg-red-200'
                      : 'bg-green-100 text-green-700 hover:bg-green-200'
                  }`}
                >
                  {honeypotStatus[protocol] ? <><Square className="w-3 h-3 inline mr-1"/>Stop</> : <><Play className="w-3 h-3 inline mr-1"/>Start</>}
                </button>
              </button>
            ))}
          </div>
        </div>

        {/* Configuration Form */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Basic Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-800 border-b border-gray-200 pb-2">Basic Settings</h3>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Host</label>
              <input
                type="text"
                value={currentConfig.host || '0.0.0.0'}
                onChange={(e) => handleConfigChange('host', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
              <input
                type="number"
                value={currentConfig.port || ''}
                onChange={(e) => handleConfigChange('port', parseInt(e.target.value))}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Hostname</label>
              <input
                type="text"
                value={currentConfig.hostname || ''}
                onChange={(e) => handleConfigChange('hostname', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Banner</label>
              <textarea
                value={currentConfig.banner || ''}
                onChange={(e) => handleConfigChange('banner', e.target.value)}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-gray-400 focus:border-transparent"
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                checked={currentConfig.allow_all_logins || false}
                onChange={(e) => handleConfigChange('allow_all_logins', e.target.checked)}
                className="w-4 h-4 text-gray-600 border-gray-300 rounded focus:ring-gray-400"
              />
              <label className="ml-2 text-sm text-gray-700">Allow All Logins</label>
            </div>
          </div>

          {/* Advanced Settings */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-800 border-b border-gray-200 pb-2">Advanced Settings</h3>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Valid Credentials</label>
              <textarea
                value={JSON.stringify(currentConfig.valid_credentials || {}, null, 2)}
                onChange={(e) => {
                  try {
                    handleConfigChange('valid_credentials', JSON.parse(e.target.value));
                  } catch {}
                }}
                rows={5}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-gray-400 focus:border-transparent"
                placeholder='{"username": "password"}'
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Filesystem Structure</label>
              <textarea
                value={JSON.stringify(currentConfig.filesystem || {}, null, 2)}
                onChange={(e) => {
                  try {
                    handleConfigChange('filesystem', JSON.parse(e.target.value));
                  } catch {}
                }}
                rows={6}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-gray-400 focus:border-transparent"
                placeholder='{"/": ["bin", "etc"]}'
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Custom Files</label>
              <textarea
                value={JSON.stringify(currentConfig.files || {}, null, 2)}
                onChange={(e) => {
                  try {
                    handleConfigChange('files', JSON.parse(e.target.value));
                  } catch {}
                }}
                rows={5}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-gray-400 focus:border-transparent"
                placeholder='{"/etc/passwd": "content"}'
              />
            </div>
          </div>
        </div>

        <div className="mt-6 flex justify-end">
          <button
            onClick={saveConfig}
            disabled={saving}
            className="flex items-center px-6 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-800 disabled:opacity-50"
          >
            <Save className="w-4 h-4 mr-2"/>
            {saving ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </div>
    </div>
  );
};

// Main App Component
const App = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-gray-700"/>
              <h1 className="text-2xl font-bold text-gray-800">IoT Honeypot Service</h1>
            </div>
            <nav className="flex space-x-1">
              <button
                onClick={() => setCurrentPage('dashboard')}
                className={`flex items-center px-4 py-2 rounded-lg transition-colors ${
                  currentPage === 'dashboard'
                    ? 'bg-gray-100 text-gray-900'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Activity className="w-4 h-4 mr-2"/>
                Dashboard
              </button>
              <button
                onClick={() => setCurrentPage('settings')}
                className={`flex items-center px-4 py-2 rounded-lg transition-colors ${
                  currentPage === 'settings'
                    ? 'bg-gray-100 text-gray-900'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Settings className="w-4 h-4 mr-2"/>
                Settings
              </button>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentPage === 'dashboard' ? <Dashboard /> : <SettingsPage />}
      </main>
    </div>
  );
};

export default App;