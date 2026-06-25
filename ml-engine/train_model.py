import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

def generate_synthetic_data(num_samples=5000):
    np.random.seed(42)
    
    # Feature columns: 
    # [packet_count, avg_packet_size, tcp_syn_count, tcp_ack_count, tcp_rst_count, protocol_tcp_ratio, protocol_udp_ratio]
    
    # 1. Normal Traffic (Label: 0, "Normal")
    # Moderate packet count, medium-to-large sizes, balanced flags, mixed protocols
    normal_samples = int(num_samples * 0.6)
    normal_packet_count = np.random.normal(50, 15, normal_samples).clip(5, 150)
    normal_avg_size = np.random.normal(500, 150, normal_samples).clip(64, 1500)
    normal_syn = np.random.normal(5, 2, normal_samples).clip(0, 15)
    normal_ack = np.random.normal(45, 12, normal_samples).clip(5, 130)
    normal_rst = np.random.normal(1, 1, normal_samples).clip(0, 5)
    normal_tcp = np.random.uniform(0.7, 0.9, normal_samples)
    normal_udp = 1.0 - normal_tcp
    
    df_normal = pd.DataFrame({
        'packet_count': normal_packet_count,
        'avg_packet_size': normal_avg_size,
        'tcp_syn_count': normal_syn,
        'tcp_ack_count': normal_ack,
        'tcp_rst_count': normal_rst,
        'protocol_tcp_ratio': normal_tcp,
        'protocol_udp_ratio': normal_udp,
        'anomaly': 1, # Isolation Forest: 1 is inlier (normal)
        'label': 'Normal'
    })

    # 2. DoS (DDoS/SYN Flood) Traffic (Label: -1, "DoS")
    # Extremely high packet count, tiny average packet size, massive SYN counts, low ACK, TCP protocol dominated
    dos_samples = int(num_samples * 0.15)
    dos_packet_count = np.random.normal(1500, 300, dos_samples).clip(800, 3000)
    dos_avg_size = np.random.normal(64, 10, dos_samples).clip(40, 120)
    dos_syn = np.random.normal(1400, 280, dos_samples).clip(700, 2900)
    dos_ack = np.random.normal(50, 20, dos_samples).clip(0, 100)
    dos_rst = np.random.normal(5, 5, dos_samples).clip(0, 20)
    dos_tcp = np.random.uniform(0.95, 1.0, dos_samples)
    dos_udp = 1.0 - dos_tcp

    df_dos = pd.DataFrame({
        'packet_count': dos_packet_count,
        'avg_packet_size': dos_avg_size,
        'tcp_syn_count': dos_syn,
        'tcp_ack_count': dos_ack,
        'tcp_rst_count': dos_rst,
        'protocol_tcp_ratio': dos_tcp,
        'protocol_udp_ratio': dos_udp,
        'anomaly': -1, # Isolation Forest: -1 is outlier (anomaly)
        'label': 'DoS'
    })

    # 3. Port Scan (Label: -1, "Port Scan")
    # High packet count, tiny sizes, high SYN or RST flags, almost no ACK,TCP-only
    scan_samples = int(num_samples * 0.15)
    scan_packet_count = np.random.normal(600, 100, scan_samples).clip(300, 1000)
    scan_avg_size = np.random.normal(60, 5, scan_samples).clip(40, 80)
    scan_syn = np.random.normal(580, 95, scan_samples).clip(280, 980)
    scan_ack = np.random.normal(5, 5, scan_samples).clip(0, 20)
    scan_rst = np.random.normal(15, 10, scan_samples).clip(0, 50)
    scan_tcp = np.random.uniform(0.98, 1.0, scan_samples)
    scan_udp = 1.0 - scan_tcp

    df_scan = pd.DataFrame({
        'packet_count': scan_packet_count,
        'avg_packet_size': scan_avg_size,
        'tcp_syn_count': scan_syn,
        'tcp_ack_count': scan_ack,
        'tcp_rst_count': scan_rst,
        'protocol_tcp_ratio': scan_tcp,
        'protocol_udp_ratio': scan_udp,
        'anomaly': -1,
        'label': 'Port Scan'
    })

    # 4. Brute Force Traffic (Label: -1, "Brute Force")
    # Elevated packet count, moderate packet size, high ACK and SYN (repeated connections)
    bf_samples = int(num_samples * 0.1)
    bf_packet_count = np.random.normal(250, 50, bf_samples).clip(150, 450)
    bf_avg_size = np.random.normal(120, 30, bf_samples).clip(64, 300)
    bf_syn = np.random.normal(80, 20, bf_samples).clip(40, 150)
    bf_ack = np.random.normal(160, 40, bf_samples).clip(80, 300)
    bf_rst = np.random.normal(40, 15, bf_samples).clip(10, 80)
    bf_tcp = np.random.uniform(0.9, 1.0, bf_samples)
    bf_udp = 1.0 - bf_tcp

    df_bf = pd.DataFrame({
        'packet_count': bf_packet_count,
        'avg_packet_size': bf_avg_size,
        'tcp_syn_count': bf_syn,
        'tcp_ack_count': bf_ack,
        'tcp_rst_count': bf_rst,
        'protocol_tcp_ratio': bf_tcp,
        'protocol_udp_ratio': bf_udp,
        'anomaly': -1,
        'label': 'Brute Force'
    })

    df = pd.concat([df_normal, df_dos, df_scan, df_bf], ignore_index=True)
    return df

def train_and_save_models():
    print("Generating training dataset...")
    df = generate_synthetic_data()
    
    features = [
        'packet_count', 'avg_packet_size', 'tcp_syn_count', 
        'tcp_ack_count', 'tcp_rst_count', 'protocol_tcp_ratio', 'protocol_udp_ratio'
    ]
    
    X = df[features]
    y_anomaly = df['anomaly']
    y_label = df['label']
    
    # 1. Train Unsupervised Anomaly Detector (Isolation Forest)
    # Fit ONLY on normal samples to establish the baseline of normal behavior
    print("Training Isolation Forest on normal baseline...")
    X_normal = df[df['label'] == 'Normal'][features]
    
    iso_forest = IsolationForest(contamination=0.05, random_state=42)
    iso_forest.fit(X_normal)
    
    # Test Isolation Forest on whole dataset
    if_predictions = iso_forest.predict(X)
    print("Isolation Forest evaluation (whole dataset classification of anomalies):")
    # True anomalies are -1, normal is 1
    print(pd.Series(if_predictions).value_counts())
    
    # 2. Train Supervised Classifier (Random Forest)
    # Trains on labeled data to classify the attack type
    print("Training Random Forest Threat Classifier...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_label, test_size=0.3, random_state=42, stratify=y_label)
    
    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_classifier.fit(X_train, y_train)
    
    y_pred = rf_classifier.predict(X_test)
    print("\nRandom Forest Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Create directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Save the models
    joblib.dump(iso_forest, 'models/anomaly_detector.joblib')
    joblib.dump(rf_classifier, 'models/threat_classifier.joblib')
    print("Models saved successfully in 'models/' directory!")

if __name__ == '__main__':
    train_and_save_models()
