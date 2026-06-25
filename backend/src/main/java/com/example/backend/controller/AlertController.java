package com.example.backend.controller;

import com.example.backend.model.Alert;
import com.example.backend.repository.AlertRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertRepository alertRepository;

    public AlertController(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    @GetMapping
    public ResponseEntity<List<Alert>> getAllAlerts() {
        return ResponseEntity.ok(alertRepository.findAllByOrderByCreatedAtDesc());
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<?> updateAlertStatus(@PathVariable Long id, @RequestParam String status) {
        if (!status.equalsIgnoreCase("PENDING") && 
            !status.equalsIgnoreCase("RESOLVED") && 
            !status.equalsIgnoreCase("IGNORED")) {
            return ResponseEntity.badRequest().body("Invalid status value. Choose 'PENDING', 'RESOLVED', or 'IGNORED'.");
        }

        Optional<Alert> optionalAlert = alertRepository.findById(id);
        if (optionalAlert.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Alert alert = optionalAlert.get();
        alert.setStatus(status.toUpperCase());
        alertRepository.save(alert);

        return ResponseEntity.ok(alert);
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getAlertStats() {
        List<Alert> allAlerts = alertRepository.findAll();
        
        long totalAnomalies = allAlerts.stream().filter(Alert::getIsAnomaly).count();
        long pendingAlerts = allAlerts.stream().filter(a -> "PENDING".equalsIgnoreCase(a.getStatus())).count();
        long resolvedAlerts = allAlerts.stream().filter(a -> "RESOLVED".equalsIgnoreCase(a.getStatus())).count();

        Map<String, Long> threatTypeCounts = new HashMap<>();
        for (Alert a : allAlerts) {
            if (a.getIsAnomaly()) {
                threatTypeCounts.put(a.getThreatType(), threatTypeCounts.getOrDefault(a.getThreatType(), 0L) + 1);
            }
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalAnomalies", totalAnomalies);
        stats.put("pendingAlerts", pendingAlerts);
        stats.put("resolvedAlerts", resolvedAlerts);
        stats.put("threatBreakdown", threatTypeCounts);

        return ResponseEntity.ok(stats);
    }
}
