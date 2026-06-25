import threading
import time
import random
import logging
from scapy.all import sniff, IP, TCP, UDP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class NetworkSniffer:
    def __init__(self, window_duration=5.0, callback=None):
        self.window_duration = window_duration
        self.callback = callback  # Callback function for when a window is completed
        
        # State variables
        self.is_running = False
        self.mode = "simulator"  # "live" or "simulator"
        self.simulated_attack_type = "normal"  # "normal", "dos", "scan", "bruteforce"
        
        # Thread handles
        self.sniff_thread = None
        self.timer_thread = None
        
        # Lock for aggregating window metrics safely
        self.lock = threading.Lock()
        
        # Current window statistics
        self.reset_window_stats()
        
        # Historical buffer to feed telemetry charts
        self.telemetry_history = []
        
        # Last processed metrics
        self.last_metrics = {
            "packet_count": 0,
            "avg_packet_size": 0,
            "tcp_syn_count": 0,
            "tcp_ack_count": 0,
            "tcp_rst_count": 0,
            "protocol_tcp_ratio": 0.0,
            "protocol_udp_ratio": 0.0,
            "source_ips": [],
            "dest_ips": []
        }

    def reset_window_stats(self):
        with self.lock:
            self.packet_count = 0
            self.total_packet_size = 0
            self.tcp_syn_count = 0
            self.tcp_ack_count = 0
            self.tcp_rst_count = 0
            self.tcp_count = 0
            self.udp_count = 0
            self.source_ips = set()
            self.dest_ips = set()
            self.start_time = time.time()

    def packet_handler(self, packet):
        """Processes a single captured Scapy packet."""
        if not self.is_running:
            return
            
        with self.lock:
            self.packet_count += 1
            self.total_packet_size += len(packet)
            
            if IP in packet:
                ip_layer = packet[IP]
                self.source_ips.add(ip_layer.src)
                self.dest_ips.add(ip_layer.dst)
                
                if packet.haslayer(TCP):
                    self.tcp_count += 1
                    flags = ip_layer[TCP].flags
                    if flags & 0x02:  # SYN flag
                        self.tcp_syn_count += 1
                    if flags & 0x10:  # ACK flag
                        self.tcp_ack_count += 1
                    if flags & 0x04:  # RST flag
                        self.tcp_rst_count += 1
                elif packet.haslayer(UDP):
                    self.udp_count += 1

    def aggregate_and_dispatch(self):
        """Aggregates metrics for the current window and invokes the callback."""
        with self.lock:
            duration = time.time() - self.start_time
            if duration <= 0:
                duration = 1.0
                
            p_count = self.packet_count
            avg_size = self.total_packet_size / p_count if p_count > 0 else 0
            
            tcp_ratio = self.tcp_count / p_count if p_count > 0 else 0.0
            udp_ratio = self.udp_count / p_count if p_count > 0 else 0.0
            
            metrics = {
                "packet_count": p_count,
                "avg_packet_size": avg_size,
                "tcp_syn_count": self.tcp_syn_count,
                "tcp_ack_count": self.tcp_ack_count,
                "tcp_rst_count": self.tcp_rst_count,
                "protocol_tcp_ratio": tcp_ratio,
                "protocol_udp_ratio": udp_ratio,
                "source_ips": list(self.source_ips),
                "dest_ips": list(self.dest_ips),
                "timestamp": time.time()
            }
            
            self.last_metrics = metrics
            
            # Save telemetry history (max 30 items)
            self.telemetry_history.append(metrics)
            if len(self.telemetry_history) > 30:
                self.telemetry_history.pop(0)

        # Trigger callback with metrics
        if self.callback:
            try:
                self.callback(metrics)
            except Exception as e:
                logging.error(f"Error in sniffer callback: {e}")

    def timer_loop(self):
        """Runs a periodic timer loop to dispatch metrics every N seconds."""
        while self.is_running:
            time.sleep(self.window_duration)
            if self.is_running:
                if self.mode == "simulator":
                    self.generate_simulator_data()
                self.aggregate_and_dispatch()
                self.reset_window_stats()

    def generate_simulator_data(self):
        """Generates mock packet statistics depending on simulated attack type."""
        with self.lock:
            attack = self.simulated_attack_type
            
            # Simulated source/destination IPs
            fake_sources = ["192.168.1.50", "192.168.1.100", "192.168.1.120", "10.0.0.5"]
            fake_dests = ["192.168.1.1", "10.0.0.1", "8.8.8.8"]
            
            if attack == "normal":
                self.packet_count = int(random.normalvariate(50, 10))
                self.packet_count = max(5, self.packet_count)
                self.total_packet_size = self.packet_count * int(random.normalvariate(500, 100))
                self.tcp_count = int(self.packet_count * random.uniform(0.7, 0.9))
                self.udp_count = self.packet_count - self.tcp_count
                self.tcp_syn_count = int(self.tcp_count * random.uniform(0.05, 0.1))
                self.tcp_ack_count = int(self.tcp_count * random.uniform(0.8, 0.9))
                self.tcp_rst_count = int(self.tcp_count * random.uniform(0.01, 0.05))
                self.source_ips.update(random.choices(fake_sources, k=3))
                self.dest_ips.update(random.choices(fake_dests, k=2))
                
            elif attack == "dos":
                # Simulated DDoS SYN Flood
                self.packet_count = int(random.normalvariate(1800, 200))
                self.packet_count = max(800, self.packet_count)
                self.total_packet_size = self.packet_count * int(random.normalvariate(64, 5))
                self.tcp_count = self.packet_count
                self.udp_count = 0
                self.tcp_syn_count = int(self.packet_count * random.uniform(0.95, 0.99))
                self.tcp_ack_count = self.packet_count - self.tcp_syn_count
                self.tcp_rst_count = int(random.normalvariate(5, 2))
                # Single malicious IP targeting the server
                self.source_ips.add("185.220.101.5")
                self.dest_ips.add("192.168.1.1")
                
            elif attack == "scan":
                # Simulated Fast Port Scanning
                self.packet_count = int(random.normalvariate(700, 80))
                self.packet_count = max(300, self.packet_count)
                self.total_packet_size = self.packet_count * int(random.normalvariate(60, 2))
                self.tcp_count = self.packet_count
                self.udp_count = 0
                self.tcp_syn_count = int(self.packet_count * random.uniform(0.9, 0.95))
                self.tcp_ack_count = int(self.packet_count * random.uniform(0.01, 0.05))
                self.tcp_rst_count = int(self.packet_count * random.uniform(0.02, 0.05))
                self.source_ips.add("45.143.203.12")
                self.dest_ips.add("192.168.1.1")
                
            elif attack == "bruteforce":
                # Simulated SSH/FTP Brute Force connections
                self.packet_count = int(random.normalvariate(280, 30))
                self.packet_count = max(100, self.packet_count)
                self.total_packet_size = self.packet_count * int(random.normalvariate(120, 20))
                self.tcp_count = self.packet_count
                self.udp_count = 0
                self.tcp_syn_count = int(self.packet_count * 0.3)
                self.tcp_ack_count = int(self.packet_count * 0.6)
                self.tcp_rst_count = int(self.packet_count * 0.1)
                self.source_ips.add("203.0.113.88")
                self.dest_ips.add("192.168.1.1")

    def start_live_sniffing(self):
        """Starts live packet capture via Scapy."""
        logging.info("Starting live sniffer thread...")
        try:
            # We sniff filter as ip (captures both TCP and UDP)
            sniff(prn=self.packet_handler, filter="ip", store=0, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            logging.error(f"Live sniffing failed (Ensure you run as Admin with NPcap/WinPcap): {e}")
            logging.info("Falling back to Simulator mode...")
            self.mode = "simulator"

    def start(self, mode="simulator"):
        if self.is_running:
            logging.warning("Sniffer already running.")
            return
            
        self.is_running = True
        self.mode = mode
        self.reset_window_stats()
        
        # Start periodic aggregation timer thread
        self.timer_thread = threading.Thread(target=self.timer_loop, daemon=True)
        self.timer_thread.start()
        
        # Start sniffing if live mode
        if self.mode == "live":
            self.sniff_thread = threading.Thread(target=self.start_live_sniffing, daemon=True)
            self.sniff_thread.start()
            
        logging.info(f"Sniffer engine started in [{self.mode}] mode.")

    def stop(self):
        if not self.is_running:
            return
            
        self.is_running = False
        if self.timer_thread:
            self.timer_thread.join(timeout=1.0)
        logging.info("Sniffer engine stopped.")

    def set_attack_type(self, attack_type):
        if attack_type in ["normal", "dos", "scan", "bruteforce"]:
            self.simulated_attack_type = attack_type
            logging.info(f"Simulator attack profile set to: {attack_type}")
            return True
        return False
