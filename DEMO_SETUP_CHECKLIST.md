# Pre-Demo Setup Checklist - DRRA Conference Demo

## ✅ Setup Status: IN PROGRESS

### Step 1: Start Docker Desktop ⚠️ **ACTION REQUIRED**
Docker Desktop is not currently running. You must start it manually:

**On Windows:**
1. Click Windows Start button
2. Search for "Docker Desktop"
3. Click to launch Docker Desktop
4. Wait for it to fully initialize (look for Docker icon in system tray)
5. This typically takes 30-60 seconds

**Verify Docker is running:**
```bash
docker ps
```
If this command succeeds without errors, Docker is ready.

---

### Step 2: Start All Services (After Docker is Running)
```bash
cd c:\Users\txvat\git\ransomwaredefense
docker-compose up -d
```

**Containers that will start:**
- ✅ PostgreSQL (database on port 5432)
- ✅ MinIO (S3 storage on port 9000)
- ✅ Kafka (message queue on port 9092)
- ✅ FastAPI Backend (on port 8000)
- ✅ React Dashboard (on port 3000)
- ✅ Rust File Watcher (monitoring service)

---

### Step 3: Verify Services Are Running
```bash
# Check container status
docker-compose ps

# Check backend health
curl http://localhost:8000/api/v1/health

# Expected response:
# {"status": "ok", "services": {"database": "connected", ...}}
```

---

### Step 4: Access Dashboard
Open in your browser:
```
http://localhost:3000
```

You should see the DRRA dashboard with:
- Real-time KPI cards
- Threat feed
- Defensibility Index scorecard
- Incident timeline

---

### Step 5: Run Demo Script (Optional)
For an automated 5-minute walkthrough:
```bash
python demo_attack_simulation.py --duration 90 --intensity 1.0
```

This will:
1. Deploy a simulated ransomware attack (FORGE)
2. Show real-time detection (VIGIL)
3. Display isolation and recovery (SHIELD)
4. Calculate Defensibility Index scores

---

## 🛠️ Troubleshooting

**If services don't start:**
```bash
# View logs
docker-compose logs backend

# Restart services
docker-compose restart

# Stop everything and restart clean
docker-compose down
docker-compose up -d
```

**If backend health check fails:**
```bash
# Check backend logs
docker-compose logs -f backend

# Wait 10-15 seconds and try again (services need time to initialize)
sleep 15
curl http://localhost:8000/api/v1/health
```

**If dashboard is blank:**
- Check browser console (F12) for errors
- Verify backend is responding: `curl http://localhost:8000/api/v1/health`
- Clear browser cache and refresh

---

## 📋 Demo Flow

**When ready, follow CONFERENCE_DEMO.md:**

1. **Minute 1-2**: Architecture overview (show ARCHITECTURE.md)
2. **Minute 2-3**: Deploy attack via FORGE API
3. **Minute 3-5**: Show VIGIL detection events
4. **Minute 5-7**: Show SHIELD response (isolation/recovery)
5. **Minute 7-8**: Open dashboard and show metrics
6. **Minute 8-10**: Key takeaways and Q&A

---

## ✨ Demo Success Indicators

✅ Docker Desktop is running  
✅ All containers are active (`docker-compose ps`)  
✅ Backend responds to health check  
✅ Dashboard loads at http://localhost:3000  
✅ CONFERENCE_DEMO.md is ready to follow  

---

**Next Step**: Start Docker Desktop, then run:
```bash
docker-compose up -d
```

Then verify with:
```bash
curl http://localhost:8000/api/v1/health
```

Good luck! 🚀
