"""
AI Cyber Defense & Threat Monitoring Platform
FastAPI Backend — Complete SOC Platform
"""
from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import uuid
import time
import random
import math
import hashlib
import os
import json
import threading
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

app = FastAPI(title="AI Cyber Defense Platform", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# In-Memory Database (no MongoDB needed for demo)
# ─────────────────────────────────────────────
DB = {
    "analyses": {},
    "logs": [],
    "alerts": [],
    "users": {
        "admin": {"password": "admin123", "role": "admin", "email": "admin@soc.local"},
        "analyst": {"password": "analyst123", "role": "analyst", "email": "analyst@soc.local"},
    },
    "network_events": [],
    "ids_events": [],
    "stats": {
        "total_analyses": 0,
        "threats_detected": 0,
        "blocked_attacks": 0,
        "uptime_start": time.time()
    }
}

# ─────────────────────────────────────────────
# ML Model — Isolation Forest
# ─────────────────────────────────────────────
class ThreatMLEngine:
    def __init__(self):
        self.model = IsolationForest(n_estimators=200, contamination=0.08, random_state=42)
        self.scaler = StandardScaler()
        self._trained = False
        self._train_with_synthetic_data()

    def _train_with_synthetic_data(self):
        """Train on synthetic benign + malicious behavior patterns"""
        rng = np.random.RandomState(42)
        # Benign samples: low counts, normal entropy
        benign = np.column_stack([
            rng.poisson(2, 500),      # process_count
            rng.poisson(1, 500),      # network_attempts
            rng.poisson(3, 500),      # file_write_count
            rng.binomial(1, 0.02, 500),  # sensitive_path_hits
            rng.binomial(1, 0.01, 500),  # registry_writes
            rng.poisson(5, 500),      # high_rate_syscalls
            rng.uniform(3.5, 6.5, 500),  # entropy_score
            rng.poisson(1, 500),      # unique_dst_ips
        ])
        # Malicious: high counts, anomalous patterns
        malicious = np.column_stack([
            rng.poisson(15, 100),
            rng.poisson(20, 100),
            rng.poisson(25, 100),
            rng.binomial(1, 0.8, 100),
            rng.binomial(1, 0.6, 100),
            rng.poisson(50, 100),
            rng.uniform(6.8, 8.0, 100),
            rng.poisson(12, 100),
        ])
        X = np.vstack([benign, malicious])
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._trained = True

    def predict(self, features: dict) -> dict:
        feature_vec = np.array([[
            features.get("process_count", 1),
            features.get("network_attempts", 0),
            features.get("file_write_count", 2),
            features.get("sensitive_path_hits", 0),
            features.get("registry_writes", 0),
            features.get("high_rate_syscalls", 3),
            features.get("entropy_score", 5.0),
            features.get("unique_dst_ips", 1),
        ]])
        scaled = self.scaler.transform(feature_vec)
        score = self.model.decision_function(scaled)[0]
        # Convert anomaly score to risk 0-100
        risk_score = max(0, min(100, int((1 - score) * 55 + random.uniform(-3, 3))))
        if risk_score >= 75:
            risk_level = "Critical"
        elif risk_score >= 55:
            risk_level = "High"
        elif risk_score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        return {"risk_score": risk_score, "risk_level": risk_level, "anomaly_score": round(float(score), 4)}

ml_engine = ThreatMLEngine()

# ─────────────────────────────────────────────
# Threat Intelligence Data
# ─────────────────────────────────────────────
KNOWN_C2_IPS = [
    "185.220.101.47", "185.220.101.34", "51.77.135.89",
    "194.165.16.11", "45.142.212.100", "91.219.236.166",
    "185.56.80.65", "193.32.161.10", "45.61.136.47",
]
MITRE_MAPPING = {
    "c2_communication": ("T1071", "Application Layer Protocol"),
    "persistence": ("T1547", "Boot or Logon Autostart Execution"),
    "privilege_escalation": ("T1548", "Abuse Elevation Control Mechanism"),
    "lateral_movement": ("T1021", "Remote Services"),
    "data_exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "process_injection": ("T1055", "Process Injection"),
    "dropper": ("T1059", "Command and Scripting Interpreter"),
    "obfuscation": ("T1027", "Obfuscated Files or Information"),
    "credential_access": ("T1003", "OS Credential Dumping"),
    "discovery": ("T1082", "System Information Discovery"),
    "port_scan": ("T1046", "Network Service Discovery"),
    "ddos": ("T1498", "Network Denial of Service"),
}
ATTACK_TYPES = ["DDoS", "Port Scan", "SQL Injection", "Brute Force", "C2 Beacon",
                "XSS", "CSRF", "RCE Attempt", "Data Exfiltration", "Malware Dropper"]
SEVERITIES = ["critical", "high", "medium", "low"]
SOURCE_IPS_ATTACK = [
    "192.168.1.{}".format(i) for i in range(10, 50)
] + KNOWN_C2_IPS[:5]

# ─────────────────────────────────────────────
# Simulation Engine — generates live events
# ─────────────────────────────────────────────
def generate_network_event():
    is_attack = random.random() < 0.25
    src = random.choice(SOURCE_IPS_ATTACK if is_attack else
                        ["10.0.0.{}".format(i) for i in range(1,50)])
    dst = random.choice(["10.0.0.1", "10.0.0.2", "192.168.0.1", "8.8.8.8"])
    proto = random.choice(["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"])
    port = random.choice([80, 443, 22, 3306, 8080, 8443, 21, 25, 53, 445, 3389])
    return {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "protocol": proto,
        "port": port,
        "bytes": random.randint(64, 65000),
        "is_attack": is_attack,
        "attack_type": random.choice(ATTACK_TYPES) if is_attack else None,
        "severity": random.choice(["high", "critical"]) if is_attack else "info",
    }

def generate_ids_event():
    attack = random.random() < 0.3
    return {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().isoformat(),
        "rule": random.choice(["ET.SCAN.PortScan", "ET.MALWARE.C2", "ET.DOS.DDoS",
                               "ET.SQL.Injection", "ET.BRUTE.SSH", "ET.WEB.XSS"]),
        "src": ".".join([str(random.randint(1,254)) for _ in range(4)]),
        "severity": random.choice(SEVERITIES) if attack else "low",
        "action": "BLOCK" if attack else "ALLOW",
        "mitre": random.choice(list(MITRE_MAPPING.values())),
    }

def background_event_generator():
    """Continuously generate network events in background"""
    while True:
        ev = generate_network_event()
        DB["network_events"].append(ev)
        if len(DB["network_events"]) > 500:
            DB["network_events"] = DB["network_events"][-500:]
        if ev["is_attack"]:
            DB["ids_events"].append(generate_ids_event())
            if len(DB["ids_events"]) > 300:
                DB["ids_events"] = DB["ids_events"][-300:]
            DB["stats"]["blocked_attacks"] += 1
        time.sleep(random.uniform(0.4, 1.2))

# Start background thread
bg_thread = threading.Thread(target=background_event_generator, daemon=True)
bg_thread.start()

# ─────────────────────────────────────────────
# Sandbox Analysis Engine
# ─────────────────────────────────────────────
def run_sandbox_analysis(analysis_id: str, filename: str, file_size: int, file_hash: str):
    """Simulate sandbox execution and generate behavioral report"""
    time.sleep(random.uniform(3, 8))  # Simulate execution time

    # Determine threat profile based on filename hints
    is_malicious = any(k in filename.lower() for k in
                       ["malware", "trojan", "rat", "bot", "ransom", "spy", "keylog", "shell",
                        "payload", "inject", "exploit", "rootkit", "worm"])
    threat_level = "high" if is_malicious else random.choice(["low", "low", "medium", "high"])

    # Generate behavioral features
    features = {
        "process_count": random.randint(8, 30) if threat_level in ["medium","high"] else random.randint(1, 5),
        "network_attempts": random.randint(10, 50) if threat_level == "high" else random.randint(0, 3),
        "file_write_count": random.randint(15, 40) if threat_level in ["medium","high"] else random.randint(0, 5),
        "sensitive_path_hits": random.randint(3, 8) if threat_level == "high" else 0,
        "registry_writes": random.randint(2, 6) if threat_level == "high" else 0,
        "high_rate_syscalls": random.randint(30, 80) if threat_level == "high" else random.randint(2, 10),
        "entropy_score": round(random.uniform(6.5, 7.9), 2) if threat_level == "high" else round(random.uniform(3.0, 5.5), 2),
        "unique_dst_ips": random.randint(5, 20) if threat_level == "high" else random.randint(0, 2),
    }
    prediction = ml_engine.predict(features)

    # Generate processes
    procs = [{"name": "explorer.exe", "pid": 1000, "ppid": 4, "cmdline": "explorer.exe"}]
    if threat_level in ["medium", "high"]:
        procs += [
            {"name": "cmd.exe", "pid": 2345, "ppid": 1000, "cmdline": "cmd.exe /c whoami"},
            {"name": "powershell.exe", "pid": 2346, "ppid": 2345, "cmdline": "powershell -nop -w hidden -enc SQBFAFgA"},
            {"name": "svchost.exe", "pid": 3100, "ppid": 2346, "cmdline": "svchost.exe -k netsvcs"},
        ]
    if threat_level == "high":
        procs += [
            {"name": "regsvr32.exe", "pid": 4001, "ppid": 2346, "cmdline": "regsvr32.exe /s payload.dll"},
            {"name": "wscript.exe", "pid": 4200, "ppid": 4001, "cmdline": "wscript.exe dropper.vbs"},
        ]

    # Network calls
    net_calls = []
    if features["network_attempts"] > 5:
        c2 = random.choice(KNOWN_C2_IPS)
        net_calls = [
            {"dst_ip": c2, "dst_port": 4444, "protocol": "TCP", "label": "C2", "bytes": 4800},
            {"dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP", "label": "DNS", "bytes": 64},
            {"dst_ip": "1.1.1.1", "dst_port": 443, "protocol": "HTTPS", "label": "Exfil?", "bytes": random.randint(10000,500000)},
        ]

    # File ops
    file_ops = []
    if threat_level == "high":
        file_ops = [
            {"path": "C:\\Windows\\System32\\payload.dll", "op": "CREATE", "severity": "high"},
            {"path": "C:\\Users\\AppData\\Roaming\\startup.bat", "op": "WRITE", "severity": "critical"},
            {"path": "C:\\Windows\\Temp\\exfil.zip", "op": "CREATE", "severity": "high"},
        ]

    # Registry changes
    reg_changes = []
    if features["registry_writes"] > 0:
        reg_changes = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MalLoader",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Dropper",
        ]

    # Suspicious behaviors
    behaviors = []
    mitre_tags = []
    if features["network_attempts"] > 5:
        behaviors.append("C2 communication detected to known malicious IP")
        mitre_tags.append(MITRE_MAPPING["c2_communication"][0])
    if features["registry_writes"] > 0:
        behaviors.append("Registry persistence key written")
        mitre_tags.append(MITRE_MAPPING["persistence"][0])
    if features["sensitive_path_hits"] > 2:
        behaviors.append("Writes to sensitive system paths detected")
        mitre_tags.append(MITRE_MAPPING["dropper"][0])
    if features["entropy_score"] > 6.5:
        behaviors.append("High entropy binary detected (possible packing/encryption)")
        mitre_tags.append(MITRE_MAPPING["obfuscation"][0])
    if features["unique_dst_ips"] > 5:
        behaviors.append("Beaconing pattern: multiple unique C2 IPs contacted")
        mitre_tags.append(MITRE_MAPPING["data_exfiltration"][0])

    report = {
        "risk_level": prediction["risk_level"],
        "risk_score": prediction["risk_score"],
        "ml_anomaly_score": prediction["anomaly_score"],
        "suspicious_behaviors": behaviors,
        "processes_created": procs,
        "network_calls": net_calls,
        "file_operations": file_ops,
        "registry_changes": reg_changes,
        "mitre_tags": list(set(mitre_tags)),
        "behavioral_features": features,
        "analysis_duration_ms": random.randint(8000, 14000),
        "sandbox_flags": ["--network none", "--memory 256m", "--read-only", "--security-opt no-new-privileges"],
    }

    DB["analyses"][analysis_id].update({
        "status": "completed",
        "completed_at": datetime.now().isoformat(),
        "report": report,
    })
    DB["stats"]["total_analyses"] += 1
    if prediction["risk_level"] in ["High", "Critical"]:
        DB["stats"]["threats_detected"] += 1

    # Add log entry
    DB["logs"].append({
        "id": str(uuid.uuid4())[:8],
        "event": "analysis_completed",
        "analysis_id": analysis_id,
        "filename": filename,
        "risk_level": prediction["risk_level"],
        "risk_score": prediction["risk_score"],
        "severity": prediction["risk_level"].lower(),
        "timestamp": datetime.now().isoformat(),
    })

# ─────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(body: dict):
    username = body.get("username", "")
    password = body.get("password", "")
    if username in DB["users"] and DB["users"][username]["password"] == password:
        user = DB["users"][username]
        token = hashlib.sha256(f"{username}{time.time()}secret".encode()).hexdigest()[:32]
        return {
            "success": True,
            "token": token,
            "username": username,
            "role": user["role"],
            "email": user["email"],
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

# ─────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────
@app.get("/api/health")
async def health():
    uptime = int(time.time() - DB["stats"]["uptime_start"])
    return {
        "status": "healthy",
        "version": "2.0.0",
        "uptime_seconds": uptime,
        "ml_model": "IsolationForest (trained)",
        "database": "in-memory",
        "timestamp": datetime.now().isoformat(),
    }

# ─────────────────────────────────────────────
# SANDBOX / MALWARE ANALYSIS ROUTES
# ─────────────────────────────────────────────
@app.post("/api/upload")
async def upload_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > 52_428_800:  # 50MB
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")

    allowed_extensions = {".exe", ".dll", ".pdf", ".jar", ".zip", ".doc",
                          ".docx", ".js", ".py", ".sh", ".bat", ".ps1", ".vbs", ".msi"}
    ext = os.path.splitext(file.filename or "sample")[1].lower()
    if ext and ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"File type {ext} not supported")

    analysis_id = str(uuid.uuid4())
    file_hash = {
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }

    DB["analyses"][analysis_id] = {
        "analysis_id": analysis_id,
        "filename": file.filename,
        "file_size": len(content),
        "file_hashes": file_hash,
        "status": "running",
        "uploaded_at": datetime.now().isoformat(),
        "completed_at": None,
        "report": None,
    }

    background_tasks.add_task(run_sandbox_analysis, analysis_id,
                               file.filename or "sample", len(content), file_hash["sha256"])
    return {
        "analysis_id": analysis_id,
        "filename": file.filename,
        "file_size": len(content),
        "status": "running",
        "message": "File uploaded. Analysis started in sandbox.",
    }

@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    if analysis_id not in DB["analyses"]:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return DB["analyses"][analysis_id]

@app.get("/api/analyses")
async def list_analyses(limit: int = 50, skip: int = 0):
    items = list(DB["analyses"].values())
    items.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
    return {"analyses": items[skip:skip+limit], "total": len(items)}

# ─────────────────────────────────────────────
# IDS / NETWORK MONITORING ROUTES
# ─────────────────────────────────────────────
@app.get("/api/network/events")
async def get_network_events(limit: int = 100):
    evs = DB["network_events"][-limit:]
    evs.reverse()
    return {"events": evs, "total": len(DB["network_events"])}

@app.get("/api/ids/events")
async def get_ids_events(limit: int = 100, severity: Optional[str] = None):
    evs = DB["ids_events"][-300:]
    if severity:
        evs = [e for e in evs if e.get("severity") == severity]
    evs.reverse()
    return {"events": evs[:limit], "total": len(evs)}

@app.post("/api/ids/analyze")
async def analyze_traffic(body: dict):
    """Run ML anomaly detection on provided features"""
    features = body.get("features", {})
    result = ml_engine.predict(features)
    return {
        "prediction": result,
        "timestamp": datetime.now().isoformat(),
        "model": "IsolationForest",
        "features_used": features,
    }

# ─────────────────────────────────────────────
# LOGS
# ─────────────────────────────────────────────
@app.get("/api/logs")
async def get_logs(limit: int = 100, severity: Optional[str] = None):
    logs = list(DB["logs"])
    if severity:
        logs = [l for l in logs if l.get("severity") == severity]
    logs.reverse()
    return {"logs": logs[:limit], "total": len(logs)}

# ─────────────────────────────────────────────
# STATS / DASHBOARD
# ─────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    analyses = list(DB["analyses"].values())
    by_risk = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_time = 0
    completed = 0
    for a in analyses:
        if a.get("status") == "completed" and a.get("report"):
            rl = a["report"].get("risk_level", "Low")
            by_risk[rl] = by_risk.get(rl, 0) + 1
            completed += 1
            total_time += a["report"].get("analysis_duration_ms", 0)

    attack_count = sum(1 for e in DB["network_events"] if e.get("is_attack"))
    total_net = len(DB["network_events"])

    # Time-series for last 12 hours (simulated)
    now = datetime.now()
    timeline = []
    for i in range(12, -1, -1):
        t = now - timedelta(hours=i)
        timeline.append({
            "hour": t.strftime("%H:00"),
            "attacks": random.randint(2, 25),
            "normal": random.randint(50, 200),
        })

    return {
        "total_analyses": len(analyses),
        "completed": completed,
        "by_risk": by_risk,
        "threat_detection_rate": round(sum(by_risk[k] for k in ["High","Critical"]) / max(completed,1) * 100, 1),
        "avg_analysis_time_ms": int(total_time / max(completed, 1)),
        "network_events": total_net,
        "attack_count": attack_count,
        "blocked_attacks": DB["stats"]["blocked_attacks"],
        "ids_events": len(DB["ids_events"]),
        "timeline": timeline,
        "uptime_seconds": int(time.time() - DB["stats"]["uptime_start"]),
    }

@app.get("/api/threat-intel")
async def threat_intel():
    """Return current threat intelligence summary"""
    return {
        "known_c2_ips": len(KNOWN_C2_IPS),
        "active_mitre_techniques": len(MITRE_MAPPING),
        "last_updated": datetime.now().isoformat(),
        "top_threats": [
            {"name": "C2 Communication", "count": random.randint(10,50), "severity": "critical"},
            {"name": "Persistence Mechanism", "count": random.randint(5,30), "severity": "high"},
            {"name": "Data Exfiltration", "count": random.randint(3,20), "severity": "high"},
            {"name": "Process Injection", "count": random.randint(2,15), "severity": "medium"},
            {"name": "Obfuscated Payload", "count": random.randint(5,25), "severity": "medium"},
        ],
        "mitre_heatmap": [
            {"technique": v[0], "name": v[1], "count": random.randint(1,30)}
            for v in list(MITRE_MAPPING.values())[:10]
        ],
    }

# ─────────────────────────────────────────────
# Serve Frontend
# ─────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
@app.get("/{full_path:path}", response_class=HTMLResponse)
async def serve_frontend(full_path: str = ""):
    try:
        with open("/home/claude/cyberdefense/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Frontend not found</h1>", status_code=404)

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🛡️  AI Cyber Defense Platform v2.0")
    print("="*60)
    print("🌐  Open: http://localhost:8000")
    print("📖  API Docs: http://localhost:8000/docs")
    print("👤  Login: admin / admin123")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
