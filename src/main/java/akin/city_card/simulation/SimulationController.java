package akin.city_card.simulation;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/simulation")
@Slf4j
@ConditionalOnProperty(name = "simulation.enabled", havingValue = "true")
public class SimulationController {

    @Autowired
    private BusSimulationService simulationService;

    @PostMapping("/start")
    public ResponseEntity<Map<String, Object>> startAllSimulations() {
        try {
            log.info("Starting all bus simulations via API request");
            simulationService.startAllBusSimulations();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "All bus simulations started successfully");
            response.put("activeSimulations", simulationService.getActiveSimulationCount());
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to start all simulations", e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to start simulations: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    @PostMapping("/stop")
    public ResponseEntity<Map<String, Object>> stopAllSimulations() {
        try {
            log.info("Stopping all bus simulations via API request");
            simulationService.stopAllSimulations();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "All bus simulations stopped successfully");
            response.put("activeSimulations", 0);
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to stop all simulations", e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to stop simulations: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    @PostMapping("/bus/{busId}/start")
    public ResponseEntity<Map<String, Object>> startBusSimulation(@PathVariable Long busId) {
        try {
            log.info("Starting simulation for bus: {}", busId);
            simulationService.startBusSimulationById(busId);

            BusSimulationService.BusSimulationStatus status = simulationService.getSimulationStatus(busId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Bus simulation started successfully");
            response.put("busId", busId);
            response.put("status", createStatusMap(status));
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to start simulation for bus: {}", busId, e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to start bus simulation: " + e.getMessage());
            response.put("busId", busId);
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/bus/{busId}/stop")
    public ResponseEntity<Map<String, Object>> stopBusSimulation(@PathVariable Long busId) {
        try {
            log.info("Stopping simulation for bus: {}", busId);
            simulationService.stopBusSimulation(busId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Bus simulation stopped successfully");
            response.put("busId", busId);
            response.put("isRunning", false);
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to stop simulation for bus: {}", busId, e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to stop bus simulation: " + e.getMessage());
            response.put("busId", busId);
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    @PostMapping("/bus/{busId}/restart")
    public ResponseEntity<Map<String, Object>> restartBusSimulation(@PathVariable Long busId) {
        try {
            log.info("Restarting simulation for bus: {}", busId);
            simulationService.restartBusSimulation(busId);

            BusSimulationService.BusSimulationStatus status = simulationService.getSimulationStatus(busId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Bus simulation restarted successfully");
            response.put("busId", busId);
            response.put("status", createStatusMap(status));
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to restart simulation for bus: {}", busId, e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to restart bus simulation: " + e.getMessage());
            response.put("busId", busId);
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getSimulationStatus() {
        try {
            Map<String, Object> status = new HashMap<>();
            status.put("activeSimulations", simulationService.getActiveSimulationCount());
            status.put("simulationEnabled", true);
            status.put("success", true);
            status.put("timestamp", LocalDateTime.now());
            return ResponseEntity.ok(status);
        } catch (Exception e) {
            log.error("Failed to get simulation status", e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to get status: " + e.getMessage());
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    @GetMapping("/bus/{busId}/status")
    public ResponseEntity<Map<String, Object>> getBusSimulationStatus(@PathVariable Long busId) {
        try {
            BusSimulationService.BusSimulationStatus status = simulationService.getSimulationStatus(busId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("busId", busId);
            response.put("status", createStatusMap(status));
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to get simulation status for bus: {}", busId, e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to get bus status: " + e.getMessage());
            response.put("busId", busId);
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.internalServerError().body(response);
        }
    }

    @PostMapping("/bus/{busId}/switch-direction")
    public ResponseEntity<Map<String, Object>> switchBusDirection(@PathVariable Long busId) {
        try {
            log.info("Manually switching direction for bus: {}", busId);

            // Restart simulation to trigger direction switch
            simulationService.restartBusSimulation(busId);

            BusSimulationService.BusSimulationStatus status = simulationService.getSimulationStatus(busId);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Bus direction switched successfully");
            response.put("busId", busId);
            response.put("status", createStatusMap(status));
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to switch direction for bus: {}", busId, e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to switch bus direction: " + e.getMessage());
            response.put("busId", busId);
            response.put("timestamp", LocalDateTime.now());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("simulationEnabled", true);
        health.put("activeSimulations", simulationService.getActiveSimulationCount());
        health.put("timestamp", LocalDateTime.now());
        return ResponseEntity.ok(health);
    }

    private Map<String, Object> createStatusMap(BusSimulationService.BusSimulationStatus status) {
        Map<String, Object> statusMap = new HashMap<>();
        statusMap.put("isRunning", status.isRunning());

        if (status.isRunning()) {
            statusMap.put("currentNodeIndex", status.getCurrentNodeIndex());
            statusMap.put("currentProgress", Math.round(status.getCurrentProgress() * 100.0) / 100.0); // Round to 2 decimals
            statusMap.put("currentProgressPercent", Math.round(status.getCurrentProgress() * 100.0));
            statusMap.put("isAtStation", status.isAtStation());
            statusMap.put("currentRouteSegment", status.getCurrentRouteSegment());
        }

        return statusMap;
    }
}