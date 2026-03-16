import React from 'react';
import { Shield, AlertCircle } from 'lucide-react';

const DefensibilityScorecard = () => {
  const scores = {
    overall: 78,
    detection: 85,
    isolation: 72,
    recovery: 75,
    immutability: 76,
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getScoreBgColor = (score) => {
    if (score >= 80) return 'bg-green-900 border-green-700';
    if (score >= 60) return 'bg-yellow-900 border-yellow-700';
    return 'bg-red-900 border-red-700';
  };

  return (
    <div className="bg-slate-900 rounded-lg p-6 border border-slate-700">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Shield className="w-5 h-5 text-blue-500" />
        Defensibility Index
      </h3>

      {/* Overall Score */}
      <div className={`rounded-lg p-4 border mb-4 ${getScoreBgColor(scores.overall)}`}>
        <p className="text-xs text-slate-300 mb-2">OVERALL SCORE</p>
        <p className={`text-4xl font-bold ${getScoreColor(scores.overall)}`}>
          {scores.overall}
          <span className="text-lg opacity-75">/100</span>
        </p>
      </div>

      {/* Component Scores */}
      <div className="space-y-3">
        {Object.entries(scores).filter(([key]) => key !== 'overall').map(([component, score]) => (
          <div key={component}>
            <div className="flex justify-between items-center mb-1">
              <p className="text-sm font-medium capitalize">{component.replace('_', ' ')}</p>
              <p className={`text-sm font-bold ${getScoreColor(score)}`}>{score}</p>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2">
              <div
                className={`h-2 rounded-full transition-all ${
                  score >= 80 ? 'bg-green-500' :
                  score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${score}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Recommendations */}
      <div className="mt-6 pt-4 border-t border-slate-700">
        <p className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1">
          <AlertCircle className="w-4 h-4" /> Improve by:
        </p>
        <ul className="text-xs text-slate-400 space-y-1">
          <li>• Enable immutable backup retention</li>
          <li>• Implement network segmentation</li>
          <li>• Deploy EDR solution</li>
        </ul>
      </div>
    </div>
  );
};

export default DefensibilityScorecard;
