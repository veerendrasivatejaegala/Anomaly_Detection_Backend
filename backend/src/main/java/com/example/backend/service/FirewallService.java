package com.example.backend.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@Service
public class FirewallService {

    private static final Logger logger = LoggerFactory.getLogger(FirewallService.class);

    public boolean blockIp(String ip) {
        String os = System.getProperty("os.name").toLowerCase();
        String command;

        if (os.contains("win")) {
            // Windows netsh command to add inbound block rule
            command = String.format("netsh advfirewall firewall add rule name=\"AegisShield_Block_%s\" dir=in action=block remoteip=%s", ip, ip);
        } else {
            // Linux iptables command to drop input packets from IP
            command = String.format("sudo iptables -A INPUT -s %s -j DROP", ip);
        }

        return executeCommand(command);
    }

    public boolean unblockIp(String ip) {
        String os = System.getProperty("os.name").toLowerCase();
        String command;

        if (os.contains("win")) {
            // Windows command to delete the block rule
            command = String.format("netsh advfirewall firewall delete rule name=\"AegisShield_Block_%s\"", ip);
        } else {
            // Linux command to delete the iptables drop rule
            command = String.format("sudo iptables -D INPUT -s %s -j DROP", ip);
        }

        return executeCommand(command);
    }

    private boolean executeCommand(String command) {
        try {
            logger.info("Executing active firewall instruction: {}", command);
            
            Process process;
            String os = System.getProperty("os.name").toLowerCase();
            
            if (os.contains("win")) {
                process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", command});
            } else {
                process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                logger.info("OS Firewall rule successfully deployed.");
                return true;
            } else {
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorMsg = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    errorMsg.append(line).append("\n");
                }
                logger.warn("OS Firewall command failed with code {}: {}. (Note: Real firewall modifications require running the terminal/IDE as Administrator/Root)", exitCode, errorMsg.toString().trim());
                return false;
            }
        } catch (Exception e) {
            logger.error("Exception occurred while executing OS firewall command", e);
            return false;
        }
    }
}
