package com.example.backend.controller;

import com.example.backend.model.Alert;
import com.example.backend.repository.AlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/webhook")
public class WebhookController {

    private static final Logger logger = LoggerFactory.getLogger(WebhookController.class);
    private final AlertRepository alertRepository;

    public WebhookController(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    @PostMapping("/alert")
    public ResponseEntity<?> receiveAlert(@RequestBody AlertWebhookRequest request) {
        logger.info("Received threat alert webhook: {} (confidence: {}%)", request.getThreatType(), request.getConfidence() * 100);

        Alert alert = new Alert();
        alert.setTimestamp(request.getTimestamp());
        alert.setPacketCount(request.getPacketCount());
        alert.setAvgPacketSize(request.getAvgPacketSize());
        alert.setTcpSynCount(request.getTcpSynCount());
        alert.setTcpAckCount(request.getTcpAckCount());
        alert.setTcpRstCount(request.getTcpRstCount());
        alert.setProtocolTcpRatio(request.getProtocolTcpRatio());
        alert.setProtocolUdpRatio(request.getProtocolUdpRatio());
        
        // Convert lists to comma separated strings
        if (request.getSourceIps() != null) {
            alert.setSourceIps(String.join(",", request.getSourceIps()));
        }
        if (request.getDestIps() != null) {
            alert.setDestIps(String.join(",", request.getDestIps()));
        }

        alert.setIsAnomaly(request.getIsAnomaly());
        alert.setThreatType(request.getThreatType());
        alert.setConfidence(request.getConfidence());
        alert.setStatus("PENDING");

        alertRepository.save(alert);

        return ResponseEntity.ok("Alert received and recorded.");
    }

    // DTO for webhook payload
    public static class AlertWebhookRequest {
        private Double timestamp;
        private Integer packetCount;
        private Double avgPacketSize;
        private Integer tcpSynCount;
        private Integer tcpAckCount;
        private Integer tcpRstCount;
        private Double protocolTcpRatio;
        private Double protocolUdpRatio;
        private List<String> sourceIps;
        private List<String> destIps;
        private Boolean isAnomaly;
        private String threatType;
        private Double confidence;

        // Getters and Setters
        public Double getTimestamp() { return timestamp; }
        public void setTimestamp(Double timestamp) { this.timestamp = timestamp; }

        public Integer getPacketCount() { return packetCount; }
        public void setPacketCount(Integer packetCount) { this.packetCount = packetCount; }

        public Double getAvgPacketSize() { return avgPacketSize; }
        public void setAvgPacketSize(Double avgPacketSize) { this.avgPacketSize = avgPacketSize; }

        public Integer getTcpSynCount() { return tcpSynCount; }
        public void setTcpSynCount(Integer tcpSynCount) { this.tcpSynCount = tcpSynCount; }

        public Integer getTcpAckCount() { return tcpAckCount; }
        public void setTcpAckCount(Integer tcpAckCount) { this.tcpAckCount = tcpAckCount; }

        public Integer getTcpRstCount() { return tcpRstCount; }
        public void setTcpRstCount(Integer tcpRstCount) { this.tcpRstCount = tcpRstCount; }

        public Double getProtocolTcpRatio() { return protocolTcpRatio; }
        public void setProtocolTcpRatio(Double protocolTcpRatio) { this.protocolTcpRatio = protocolTcpRatio; }

        public Double getProtocolUdpRatio() { return protocolUdpRatio; }
        public void setProtocolUdpRatio(Double protocolUdpRatio) { this.protocolUdpRatio = protocolUdpRatio; }

        public List<String> getSourceIps() { return sourceIps; }
        public void setSourceIps(List<String> sourceIps) { this.sourceIps = sourceIps; }

        public List<String> getDestIps() { return destIps; }
        public void setDestIps(List<String> destIps) { this.destIps = destIps; }

        public Boolean getIsAnomaly() { return isAnomaly; }
        public void setIsAnomaly(Boolean anomaly) { isAnomaly = anomaly; }

        public String getThreatType() { return threatType; }
        public void setThreatType(String threatType) { this.threatType = threatType; }

        public Double getConfidence() { return confidence; }
        public void setConfidence(Double confidence) { this.confidence = confidence; }
    }
}
