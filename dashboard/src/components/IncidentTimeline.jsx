import React from 'react';

const IncidentTimeline = () => {
  const events = [
    { time: '10:34 AM', status: 'Detection', type: 'Mass modification detected', color: 'bg-red-500' },
    { time: '10:34 AM', status: 'Isolation', type: 'Workstation quarantined', color: 'bg-orange-500' },
    { time: '10:35 AM', status: 'Forensics', type: 'Evidence preserved', color: 'bg-yellow-500' },
    { time: '10:36 AM', status: 'Recovery', type: 'Snapshot restoration initiated', color: 'bg-green-500' },
  ];

  return (
    <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
      <h3 className="text-lg font-semibold mb-6">Incident Response Timeline</h3>
      <div className="space-y-0 relative">
        <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-slate-700" />
        {events.map((event, index) => (
          <div key={index} className="pl-10 pb-6 relative">
            <div className={`absolute left-0 w-7 h-7 rounded-full ${event.color} ring-4 ring-slate-900`} />
            <div>
              <p className="text-sm font-semibold text-slate-300">{event.status}</p>
              <p className="text-xs text-slate-400 mt-1">{event.type}</p>
              <p className="text-xs text-slate-500 mt-2">{event.time}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default IncidentTimeline;
