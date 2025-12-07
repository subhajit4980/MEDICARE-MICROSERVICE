package com.medicare.Auth_Service.Controller;



import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HealthController {


    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("UP");
    }


    @GetMapping("/ready")
    public ResponseEntity<String> ready() {
// Optionally call dependency checks here
        return ResponseEntity.ok("READY");
    }


    @GetMapping("/version")
    public ResponseEntity<String> version() {
// Read from build properties or env
        String ver = System.getenv().getOrDefault("SERVICE_VERSION","unknown");
        return ResponseEntity.ok(ver);
    }
}