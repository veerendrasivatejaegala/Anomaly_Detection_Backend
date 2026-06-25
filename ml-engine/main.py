from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import logging
import uvicorn
import os

from sniffer import NetworkSniffer
from detector import ThreatDetector
from train_model import train_and_save_models

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="Anomaly Detection ML Engine", version="1.0.0")

# Enable CORS for frontend and backend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Endpoint mappings & configurations
SPRING_BOOT_WEBHOOK_URL = os.getenv("SPRING_BOOT_WEBHOOK_URL", "http://localhost:8080/api/webhook/alert")

# Instantiate detector
detector = ThreatDetector()

# Define Callback for Sniffer
def handle_metrics_window(metrics):
    logging.info(f"Aggregated window: {metrics['packet_count']} packets, {metrics['avg_packet_size']:.2f} avg bytes")
    
    # Analyze window using ML detector
    analysis = detector.analyze_metrics(metrics)
    
    # Merge metrics with ML analysis
    alert_payload = {
        "timestamp": metrics["timestamp"],
        "packetCount": metrics["packet_count"],
        "avgPacketSize": metrics["avg_packet_size"],
        "tcpSynCount": metrics["tcp_syn_count"],
        "tcpAckCount": metrics["tcp_ack_count"],
        "tcpRstCount": metrics["tcp_rst_count"],
        "protocolTcpRatio": metrics["protocol_tcp_ratio"],
        "protocolUdpRatio": metrics["protocol_udp_ratio"],
        "sourceIps": metrics["source_ips"],
        "destIps": metrics["dest_ips"],
        "isAnomaly": analysis["is_anomaly"],
        "threatType": analysis["threat_type"],
        "confidence": analysis["confidence"]
    }
    
    # Send alert if anomalous
    if alert_payload["isAnomaly"]:
        logging.warning(f"🚨 ANOMALY DETECTED: {alert_payload['threatType']} (Confidence: {alert_payload['confidence']:.2%})")
        try:
            response = requests.post(SPRING_BOOT_WEBHOOK_URL, json=alert_payload, timeout=2.0)
            if response.status_code == 200:
                logging.info("Alert webhook successfully sent to Spring Boot.")
            else:
                logging.error(f"Spring Boot returned status code {response.status_code} on alert webhook.")
        except Exception as e:
            logging.error(f"Failed to transmit alert webhook to Spring Boot: {e}")
    else:
        logging.info("Traffic analysis: Normal behavior.")

# Instantiate sniffer
sniffer = NetworkSniffer(window_duration=5.0, callback=handle_metrics_window)

# Pydantic models for request bodies
class StartRequest(BaseModel):
    mode: str = "simulator" # "live" or "simulator"

class AttackRequest(BaseModel):
    attack_type: str # "normal", "dos", "scan", "bruteforce"

@app.get("/api/sniffer/status")
def get_status():
    return {
        "is_running": sniffer.is_running,
        "mode": sniffer.mode,
        "simulated_attack_type": sniffer.simulated_attack_type,
        "has_models": detector.anomaly_model is not None and detector.classifier_model is not None
    }

@app.post("/api/sniffer/start")
def start_sniffer(req: StartRequest):
    if req.mode not in ["live", "simulator"]:
        raise HTTPException(status_code=400, detail="Invalid mode. Choose 'live' or 'simulator'.")
    
    if sniffer.is_running:
        return {"message": "Sniffer is already running", "mode": sniffer.mode}
        
    sniffer.start(mode=req.mode)
    return {"message": f"Sniffer started in {req.mode} mode."}

@app.post("/api/sniffer/stop")
def stop_sniffer():
    if not sniffer.is_running:
        return {"message": "Sniffer is already stopped"}
        
    sniffer.stop()
    return {"message": "Sniffer stopped."}

@app.post("/api/sniffer/simulate-attack")
def simulate_attack(req: AttackRequest):
    if not sniffer.is_running:
        raise HTTPException(status_code=400, detail="Sniffer must be running to simulate an attack.")
    
    if not sniffer.mode == "simulator":
        raise HTTPException(status_code=400, detail="Attack simulation is only available in 'simulator' mode.")
        
    success = sniffer.set_attack_type(req.attack_type)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid attack type. Choose 'normal', 'dos', 'scan', or 'bruteforce'.")
        
    return {"message": f"Simulator set to trigger {req.attack_type} pattern."}

@app.get("/api/sniffer/telemetry")
def get_telemetry():
    # Returns history to the frontend to feed live dashboards
    return {
        "history": sniffer.telemetry_history,
        "last_metrics": sniffer.last_metrics
    }

@app.post("/api/sniffer/retrain")
def retrain_models(background_tasks: BackgroundTasks):
    def run_training():
        train_and_save_models()
        detector.reload()
        
    background_tasks.add_task(run_training)
    return {"message": "Model retraining started in the background."}

# Auto start simulator on run for easy development
@app.on_event("startup")
def startup_event():
    # Auto-train models if missing
    if not os.path.exists("models/anomaly_detector.joblib") or not os.path.exists("models/threat_classifier.joblib"):
        logging.info("Models not found. Training default models...")
        train_and_save_models()
        detector.reload()
    
    logging.info("Auto-starting network sniffer simulator...")
    sniffer.start(mode="simulator")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
