package com.example.backend.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "alerts")
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Double timestamp;
    private Integer packetCount;
    private Double avgPacketSize;
    private Integer tcpSynCount;
    private Integer tcpAckCount;
    private Integer tcpRstCount;
    private Double protocolTcpRatio;
    private Double protocolUdpRatio;

    @Column(columnDefinition = "TEXT")
    private String sourceIps; // Comma separated list of IPs

    @Column(columnDefinition = "TEXT")
    private String destIps; // Comma separated list of IPs

    private Boolean isAnomaly;
    private String threatType;
    private Double confidence;

    private String status; // "PENDING", "RESOLVED", "IGNORED"

    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        if (this.status == null) {
            this.status = "PENDING";
        }
    }

    public Alert() {}

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

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

    public String getSourceIps() { return sourceIps; }
    public void setSourceIps(String sourceIps) { this.sourceIps = sourceIps; }

    public String getDestIps() { return destIps; }
    public void setDestIps(String destIps) { this.destIps = destIps; }

    public Boolean getIsAnomaly() { return isAnomaly; }
    public void setIsAnomaly(Boolean anomaly) { isAnomaly = anomaly; }

    public String getThreatType() { return threatType; }
    public void setThreatType(String threatType) { this.threatType = threatType; }

    public Double getConfidence() { return confidence; }
    public void setConfidence(Double confidence) { this.confidence = confidence; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
