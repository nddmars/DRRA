import React, { useState, useEffect } from 'react';
import { AlertTriangle, Zap } from 'lucide-react';

const ThreatFeed = () => {
  const [threats, setThreats] = useState([]);

  useEffect(() => {
    // Mock threat data
    setThreats([
      {
        id: '1',
        type: 'mass_modification',
        severity: 'critical',
        timestamp: new Date(Date.now() - 5 * 60000),
        affected: '5,234 files',
        details: 'Mass file modification detected in C:\\Users',
      },
      {
        id: '2',
        type: 'encryption_detected',
        severity: 'high',
        timestamp: new Date(Date.now() - 15 * 60000),
        affected: '1,023 files',
        details: 'High entropy detected - possible encryption',
      },
      {
        id: '3',
        type: 'lateral_movement',
        severity: 'high',
        timestamp: new Date(Date.now() - 30 * 60000),
        affected: 'AD / DC01',
        details: 'Unusual Kerberos ticket requests',
      },
    ]);
  }, []);

  const getThreatColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-900 border-red-700 text-red-200';
      case 'high': return 'bg-orange-900 border-orange-700 text-orange-200';
      case 'medium': return 'bg-yellow-900 border-yellow-700 text-yellow-200';
      default: return 'bg-slate-800 border-slate-700 text-slate-200';
    }
  };

  const getThreatLabel = (type) => {
    const labels = {
      mass_modification: 'Mass Modification',
      encryption_detected: 'Encryption Detected',
      lateral_movement: 'Lateral Movement',
      vss_abuse: 'VSS Abuse',
    };
    return labels[type] || type;
  };

  return (
    <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <AlertTriangle className="w-5 h-5 text-red-500" />
        Recent Threats (Last 24h)
      </h3>
      <div className="space-y-3">
        {threats.map((threat) => (
          <div
            key={threat.id}
            className={`rounded-lg p-4 border ${getThreatColor(threat.severity)}`}
          >
            <div className="flex items-start justify-between mb-2">
              <div>
                <p className="font-semibold text-sm">{getThreatLabel(threat.type)}</p>
                <p className="text-xs opacity-75">{threat.timestamp.toLocaleTimeString()}</p>
              </div>
              <span className={`px-2 py-1 rounded text-xs font-bold ${
                threat.severity === 'critical' ? 'bg-red-700' :
                threat.severity === 'high' ? 'bg-orange-700' : 'bg-yellow-700'
              }`}>
                {threat.severity.toUpperCase()}
              </span>
            </div>
            <p className="text-sm mb-2">{threat.details}</p>
            <p className="text-xs font-mono opacity-75">Affected: {threat.affected}</p>
          </div>
        ))}
      </div>
      {threats.length === 0 && (
        <div className="text-center py-8 text-slate-400">
          <Zap className="w-12 h-12 mx-auto mb-2 opacity-50" />
          <p>No threats detected</p>
        </div>
      )}
    </div>
  );
};

export default ThreatFeed;
