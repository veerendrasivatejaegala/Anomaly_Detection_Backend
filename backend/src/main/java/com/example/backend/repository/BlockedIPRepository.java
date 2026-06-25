package com.example.backend.repository;

import com.example.backend.model.BlockedIP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BlockedIPRepository extends JpaRepository<BlockedIP, Long> {
    Optional<BlockedIP> findByIpAddress(String ipAddress);
    Boolean existsByIpAddress(String ipAddress);
}
