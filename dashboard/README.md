# Resilience Forge Dashboard Configuration

This directory contains the web dashboard for Resilience Forge.

## Features

- **Real-time Metrics**: MTTC tracking, Defensibility Index, incident status
- **Configuration Studio**: Granular threshold and policy management
- **Incident Management**: Historical and active incident analysis
- **LLM Insights**: Attack summaries and hardening recommendations
- **Community Benchmarking**: Compare your security posture with others

## Technology Stack

- **Framework**: React 18+
- **State Management**: Redux Toolkit
- **UI Components**: Material-UI
- **Charts**: Recharts
- **API Client**: Axios with React Query
- **Real-time**: WebSocket for live updates

## Quick Start

```bash
cd dashboard
npm install
npm start
```

Application will open at `http://localhost:3000`

## Environment Variables

```bash
REACT_APP_API_URL=http://localhost:8000/api/v1
REACT_APP_WS_URL=ws://localhost:8000/ws
REACT_APP_GEMINI_API_KEY=your-key-here
```

## Pages

### Dashboard Overview
- Active incidents counter
- Defensibility Index gauge
- MTTC timeline
- System health status

### Metrics
- Historical MTTC trends
- Data loss tracking
- Detection accuracy rates
- Recovery success rates

### Configuration
- Detection thresholds
- Isolation policies
- Recovery strategies
- Alert settings

### Incidents
- List of all incidents
- Detailed incident analysis
- Forensic evidence browser
- Timeline visualization

### System Health
- Component status
- Service availability
- Resource utilization
- Log analysis

## Building for Production

```bash
npm run build
```

Serves optimized build in `build/` directory.

See [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for complete information.
