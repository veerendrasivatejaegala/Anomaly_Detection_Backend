package com.example.backend.controller;

import com.example.backend.model.BlockedIP;
import com.example.backend.repository.BlockedIPRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/mitigation")
public class MitigationController {

    private final BlockedIPRepository blockedIPRepository;
    private final com.example.backend.service.FirewallService firewallService;

    public MitigationController(BlockedIPRepository blockedIPRepository, 
                                com.example.backend.service.FirewallService firewallService) {
        this.blockedIPRepository = blockedIPRepository;
        this.firewallService = firewallService;
    }

    @GetMapping("/blocked-ips")
    public ResponseEntity<List<BlockedIP>> getBlockedIPs() {
        return ResponseEntity.ok(blockedIPRepository.findAll());
    }

    @PostMapping("/block")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> blockIP(@Valid @RequestBody BlockRequest blockRequest) {
        if (blockedIPRepository.existsByIpAddress(blockRequest.getIpAddress())) {
            return ResponseEntity.badRequest().body("IP address is already blocked.");
        }

        // Retrieve current authenticated username
        String currentUser = "SYSTEM";
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            currentUser = ((UserDetails) principal).getUsername();
        } else if (principal instanceof String) {
            currentUser = (String) principal;
        }

        BlockedIP blockedIP = new BlockedIP(
                blockRequest.getIpAddress(),
                blockRequest.getReason(),
                currentUser
        );

        // Execute real OS firewall block command
        firewallService.blockIp(blockedIP.getIpAddress());

        blockedIPRepository.save(blockedIP);
        return ResponseEntity.ok(blockedIP);
    }

    @DeleteMapping("/unblock/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> unblockIP(@PathVariable Long id) {
        Optional<BlockedIP> blockedIPOptional = blockedIPRepository.findById(id);
        if (blockedIPOptional.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        BlockedIP blockedIP = blockedIPOptional.get();

        // Execute real OS firewall unblock command
        firewallService.unblockIp(blockedIP.getIpAddress());

        blockedIPRepository.delete(blockedIP);
        return ResponseEntity.ok("IP address has been unblocked.");
    }

    // Inner class for block request payload
    public static class BlockRequest {
        @NotBlank
        private String ipAddress;
        private String reason;

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }
}
