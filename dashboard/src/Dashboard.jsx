import React, { useState, useEffect } from 'react';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { AlertTriangle, CheckCircle, Clock, Activity } from 'lucide-react';
import ThreatFeed from './components/ThreatFeed';
import DefensibilityScorecard from './components/DefensibilityScorecard';
import IncidentTimeline from './components/IncidentTimeline';

const Dashboard = () => {
  const [mttc, setMttc] = useState(0);
  const [defensibility, setDefensibility] = useState(0);
  const [incidents, setIncidents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      // Fetch from backend API
      const response = await fetch('http://localhost:8000/api/v1/dashboard/summary');
      if (response.ok) {
        const data = await response.json();
        setMttc(data.metrics?.mttc_average || 0);
        setDefensibility(data.defensibility_index?.overall_score || 0);
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Sample data
  const mtTrendData = [
    { time: '00:00', mttc: 450 },
    { time: '04:00', mttc: 380 },
    { time: '08:00', mttc: 320 },
    { time: '12:00', mttc: 290 },
    { time: '16:00', mttc: 250 },
    { time: '20:00', mttc: 280 },
  ];

  const detectionData = [
    { name: 'Mass Mod', value: 32, fill: '#ef4444' },
    { name: 'Encryption', value: 18, fill: '#f97316' },
    { name: 'Lat. Move', value: 12, fill: '#eab308' },
    { name: 'VSS Abuse', value: 8, fill: '#84cc16' },
    { name: 'Network', value: 5, fill: '#22c55e' },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-white p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-2 text-red-500">🔥 Resilience Forge</h1>
        <p className="text-slate-400">Real-time ransomware defense & resilience monitoring</p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Mean Time to Contain</p>
              <p className="text-3xl font-bold text-green-400">{mttc.toFixed(0)}s</p>
            </div>
            <Clock className="w-12 h-12 text-green-500 opacity-50" />
          </div>
        </div>

        <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Defensibility Index</p>
              <p className="text-3xl font-bold text-blue-400">{defensibility}/100</p>
            </div>
            <CheckCircle className="w-12 h-12 text-blue-500 opacity-50" />
          </div>
        </div>

        <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">Active Incidents</p>
              <p className="text-3xl font-bold text-red-400">0</p>
            </div>
            <AlertTriangle className="w-12 h-12 text-red-500 opacity-50" />
          </div>
        </div>

        <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-slate-400 text-sm">System Health</p>
              <p className="text-3xl font-bold text-emerald-400">98%</p>
            </div>
            <Activity className="w-12 h-12 text-emerald-500 opacity-50" />
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* MTTC Trend */}
        <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
          <h3 className="text-lg font-semibold mb-4">MTTC Trend (24h)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={mtTrendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Area type="monotone" dataKey="mttc" stroke="#22c55e" fill="#16a34a" opacity={0.3} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Detection Patterns */}
        <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
          <h3 className="text-lg font-semibold mb-4">Detection Patterns (7d)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={detectionData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" stroke="#94a3b8" />
              <YAxis dataKey="name" type="category" stroke="#94a3b8" width={80} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Bar dataKey="value" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Threat Feed & Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ThreatFeed />
        </div>
        <div className="lg:col-span-1">
          <DefensibilityScorecard />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
