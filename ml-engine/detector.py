import joblib
import pandas as pd
import numpy as np
import logging
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class ThreatDetector:
    def __init__(self, model_dir="models"):
        self.model_dir = model_dir
        self.anomaly_detector_path = os.path.join(model_dir, "anomaly_detector.joblib")
        self.classifier_path = os.path.join(model_dir, "threat_classifier.joblib")
        
        self.anomaly_model = None
        self.classifier_model = None
        
        self.features = [
            'packet_count', 'avg_packet_size', 'tcp_syn_count', 
            'tcp_ack_count', 'tcp_rst_count', 'protocol_tcp_ratio', 'protocol_udp_ratio'
        ]
        
        self.load_models()

    def load_models(self):
        """Loads models if they exist. Otherwise, logs warnings."""
        if os.path.exists(self.anomaly_detector_path) and os.path.exists(self.classifier_path):
            try:
                self.anomaly_model = joblib.load(self.anomaly_detector_path)
                self.classifier_model = joblib.load(self.classifier_path)
                logging.info("ML Models loaded successfully.")
            except Exception as e:
                logging.error(f"Failed to load ML models: {e}")
        else:
            logging.warning("ML Models not found. Please run train_model.py first.")

    def reload(self):
        self.load_models()

    def analyze_metrics(self, metrics):
        """
        Analyzes a metrics dictionary containing network window data.
        Returns:
            dict: Analysis results containing is_anomaly, threat_type, and confidence.
        """
        if not self.anomaly_model or not self.classifier_model:
            logging.error("Models not loaded. Returning unanalyzed baseline.")
            return {
                "is_anomaly": False,
                "threat_type": "Unknown (Models Missing)",
                "confidence": 0.0,
                "features": {}
            }

        # 1. Construct the feature vector
        feature_data = {
            'packet_count': [metrics.get('packet_count', 0)],
            'avg_packet_size': [metrics.get('avg_packet_size', 0.0)],
            'tcp_syn_count': [metrics.get('tcp_syn_count', 0)],
            'tcp_ack_count': [metrics.get('tcp_ack_count', 0)],
            'tcp_rst_count': [metrics.get('tcp_rst_count', 0)],
            'protocol_tcp_ratio': [metrics.get('protocol_tcp_ratio', 0.0)],
            'protocol_udp_ratio': [metrics.get('protocol_udp_ratio', 0.0)]
        }
        
        df_features = pd.DataFrame(feature_data)
        
        # 2. Run Isolation Forest Anomaly Detection
        # Isolation Forest outputs 1 for inlier (normal), -1 for outlier (anomaly)
        anomaly_pred = self.anomaly_model.predict(df_features)[0]
        is_anomaly = (anomaly_pred == -1)
        
        # 3. Classify threat and get confidence
        # Even if Isolation Forest says normal, we run classification to cross-check.
        threat_classes = self.classifier_model.classes_
        threat_probs = self.classifier_model.predict_proba(df_features)[0]
        
        pred_index = np.argmax(threat_probs)
        predicted_threat = threat_classes[pred_index]
        confidence = float(threat_probs[pred_index])
        
        # Override anomaly decision if Random Forest is extremely confident of an attack
        # or if Isolation Forest detected it.
        final_anomaly = is_anomaly or (predicted_threat != "Normal" and confidence > 0.8)
        final_threat = predicted_threat if final_anomaly else "Normal"
        final_confidence = confidence if final_anomaly else (threat_probs[list(threat_classes).index("Normal")] if "Normal" in threat_classes else 1.0)

        # Build feature dictionary for response / logging
        features_dict = {k: v[0] for k, v in feature_data.items()}

        return {
            "is_anomaly": bool(final_anomaly),
            "threat_type": str(final_threat),
            "confidence": float(final_confidence),
            "features": features_dict
        }
