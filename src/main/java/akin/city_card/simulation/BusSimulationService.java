package akin.city_card.simulation;

import akin.city_card.bus.model.Bus;
import akin.city_card.bus.repository.BusRepository;
import akin.city_card.paymentPoint.model.Location;
import akin.city_card.route.model.Route;
import akin.city_card.route.model.RouteDirection;
import akin.city_card.route.model.RouteStationNode;
import akin.city_card.station.model.Station;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Service
@Slf4j
@ConditionalOnProperty(name = "simulation.enabled", havingValue = "true", matchIfMissing = false)
public class BusSimulationService {

    @Autowired
    private BusRepository busRepository;

    @Autowired
    private RestTemplate restTemplate;

    @Value("${simulation.thread-pool-size:25}")
    private int threadPoolSize;

    @Value("${simulation.update-interval-seconds:3}")
    private int updateIntervalSeconds;

    @Value("${simulation.auto-start:true}")
    private boolean autoStart;

    @Value("${simulation.batch-size:50}")
    private int batchSize;

    @Value("${simulation.health-check-interval:30}")
    private int healthCheckIntervalSeconds;

    private ScheduledExecutorService executorService;
    private ScheduledExecutorService healthCheckExecutor;
    private final ConcurrentHashMap<Long, ScheduledFuture<?>> runningSimulations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, BusSimulatorTask> simulatorTasks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, LocalDateTime> simulationStartTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, AtomicInteger> errorCounts = new ConcurrentHashMap<>();

    private volatile boolean initialized = false;
    private volatile boolean shutdownRequested = false;

    @PostConstruct
    public void initializeService() {
        log.info("🚌 Initializing Enhanced Bus Simulation Service...");
        log.info("📋 Configuration - ThreadPool: {}, UpdateInterval: {}s, BatchSize: {}, AutoStart: {}",
                threadPoolSize, updateIntervalSeconds, batchSize, autoStart);

        initializeExecutorService();
        startHealthCheckService();

        if (autoStart) {
            log.info("🚀 Auto-start enabled, initializing all bus simulations...");
            // Delay auto-start to ensure all beans are fully initialized
            executorService.schedule(this::startAllBusSimulations, 5, TimeUnit.SECONDS);
        }
    }

    private void initializeExecutorService() {
        if (!initialized) {
            synchronized (this) {
                if (!initialized) {
                    log.info("⚙️ Creating ScheduledExecutorService with {} threads", threadPoolSize);
                    executorService = Executors.newScheduledThreadPool(threadPoolSize,
                            r -> {
                                Thread t = new Thread(r, "BusSimulation-" + System.currentTimeMillis());
                                t.setDaemon(false);
                                return t;
                            });

                    healthCheckExecutor = Executors.newSingleThreadScheduledExecutor(
                            r -> {
                                Thread t = new Thread(r, "BusSimulation-HealthCheck");
                                t.setDaemon(true);
                                return t;
                            });

                    initialized = true;
                    log.info("✅ Executor services initialized successfully");
                }
            }
        }
    }

    private void startHealthCheckService() {
        if (healthCheckExecutor != null) {
            healthCheckExecutor.scheduleWithFixedDelay(
                    this::performHealthCheck,
                    healthCheckIntervalSeconds,
                    healthCheckIntervalSeconds,
                    TimeUnit.SECONDS
            );
            log.info("🏥 Health check service started with {}s interval", healthCheckIntervalSeconds);
        }
    }

    private void performHealthCheck() {
        try {
            if (shutdownRequested) return;

            int activeCount = getActiveSimulationCount();
            int tasksCount = simulatorTasks.size();

            log.debug("🏥 Health Check - Active: {}, Tasks: {}, Running: {}",
                    activeCount, tasksCount, runningSimulations.size());

            // Clean up completed or failed simulations
            cleanupFailedSimulations();

            // Restart failed simulations if needed
            restartFailedSimulations();

        } catch (Exception e) {
            log.error("❌ Error during health check", e);
        }
    }

    private void cleanupFailedSimulations() {
        runningSimulations.entrySet().removeIf(entry -> {
            Long busId = entry.getKey();
            ScheduledFuture<?> future = entry.getValue();

            if (future.isCancelled() || future.isDone()) {
                simulatorTasks.remove(busId);
                simulationStartTimes.remove(busId);
                log.debug("🧹 Cleaned up completed simulation for bus: {}", busId);
                return true;
            }
            return false;
        });
    }

    private void restartFailedSimulations() {
        errorCounts.entrySet().forEach(entry -> {
            Long busId = entry.getKey();
            AtomicInteger errorCount = entry.getValue();

            if (errorCount.get() > 5 && !isSimulationRunning(busId)) {
                log.warn("🔄 Attempting to restart failed simulation for bus: {} (errors: {})",
                        busId, errorCount.get());
                try {
                    startBusSimulationById(busId);
                    errorCount.set(0); // Reset error count on successful restart
                } catch (Exception e) {
                    log.error("❌ Failed to restart simulation for bus: {}", busId, e);
                }
            }
        });
    }

    @PreDestroy
    public void shutdownSimulation() {
        log.info("🛑 Shutting down Enhanced Bus Simulation Service...");
        shutdownRequested = true;
        stopAllSimulations();

        shutdownExecutorService(healthCheckExecutor, "HealthCheck", 5);
        shutdownExecutorService(executorService, "Main", 15);

        log.info("✅ Bus simulation service shutdown completed");
    }

    private void shutdownExecutorService(ScheduledExecutorService service, String name, int timeoutSeconds) {
        if (service != null && !service.isShutdown()) {
            log.info("🛑 Shutting down {} executor service...", name);
            service.shutdown();
            try {
                if (!service.awaitTermination(timeoutSeconds, TimeUnit.SECONDS)) {
                    log.warn("⚠️ {} ExecutorService did not terminate gracefully, forcing shutdown...", name);
                    service.shutdownNow();
                    if (!service.awaitTermination(5, TimeUnit.SECONDS)) {
                        log.error("❌ {} ExecutorService did not terminate after force shutdown", name);
                    }
                }
            } catch (InterruptedException e) {
                log.warn("⚠️ Interrupted while waiting for {} executor termination", name);
                service.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    @Transactional(readOnly = true)
    public void startAllBusSimulations() {
        try {
            initializeExecutorService();

            log.info("🔍 Searching for active buses...");

            // Get total count first
            long totalActiveBuses = busRepository.countByIsActiveTrueAndIsDeletedFalse();
            log.info("📊 Found {} total active buses in database", totalActiveBuses);

            if (totalActiveBuses == 0) {
                log.warn("⚠️ No active buses found in database. Check bus data and isActive/isDeleted flags.");
                return;
            }

            int startedCount = 0;
            int skippedCount = 0;
            int page = 0;

            // Process buses in batches to avoid memory issues
            while (true) {
                Pageable pageable = PageRequest.of(page, batchSize);
                List<Bus> busBatch = busRepository.findAllByIsActiveTrueAndIsDeletedFalseOrderById(pageable);

                if (busBatch.isEmpty()) {
                    break;
                }

                log.info("📦 Processing batch {} with {} buses", page + 1, busBatch.size());

                for (Bus bus : busBatch) {
                    try {
                        if (shutdownRequested) {
                            log.info("🛑 Shutdown requested, stopping simulation startup");
                            return;
                        }

                        if (canStartSimulation(bus)) {
                            startBusSimulation(bus);
                            startedCount++;

                            // Small delay between starts to prevent overwhelming the system
                            if (startedCount % 10 == 0) {
                                Thread.sleep(100);
                            }
                        } else {
                            skippedCount++;
                            log.debug("⏭️ Skipped simulation for bus {} ({}): Invalid configuration",
                                    bus.getId(), bus.getNumberPlate());
                        }
                    } catch (Exception e) {
                        skippedCount++;
                        incrementErrorCount(bus.getId());
                        log.error("❌ Failed to start simulation for bus: {} ({})",
                                bus.getId(), bus.getNumberPlate(), e);
                    }
                }

                page++;

                // Log progress
                if (page % 5 == 0) {
                    log.info("📈 Progress: Started {}, Skipped {}, Active Simulations: {}",
                            startedCount, skippedCount, getActiveSimulationCount());
                }
            }

            log.info("🎉 Simulation startup completed - Started: {}, Skipped: {}, Total Active: {}, Total Found: {}",
                    startedCount, skippedCount, getActiveSimulationCount(), totalActiveBuses);

        } catch (Exception e) {
            log.error("❌ Failed to start bus simulations", e);
            throw new RuntimeException("Failed to start all bus simulations", e);
        }
    }

    private boolean canStartSimulation(Bus bus) {
        try {
            if (bus == null) {
                log.debug("❌ Bus is null");
                return false;
            }

            if (!bus.isActive() || bus.isDeleted()) {
                log.debug("❌ Bus {} is not active or is deleted", bus.getId());
                return false;
            }

            Route assignedRoute = bus.getAssignedRoute();
            if (assignedRoute == null) {
                log.debug("❌ Bus {} has no assigned route", bus.getId());
                return false;
            }

            RouteDirection currentDirection = bus.getCurrentDirection();
            if (currentDirection == null) {
                // Try to set a default direction
                currentDirection = assignedRoute.getOutgoingDirection();
                if (currentDirection == null) {
                    currentDirection = assignedRoute.getReturnDirection();
                }

                if (currentDirection == null) {
                    log.debug("❌ Bus {} has no available directions", bus.getId());
                    return false;
                }

                bus.setCurrentDirection(currentDirection);
                log.debug("🔄 Set default direction for bus {}: {}", bus.getId(), currentDirection.getName());
            }

            List<RouteStationNode> nodes = currentDirection.getStationNodes();
            if (nodes == null || nodes.isEmpty()) {
                log.debug("❌ Bus {} has no station nodes in current direction", bus.getId());
                return false;
            }

            boolean hasValidNodes = nodes.stream().anyMatch(this::isValidNode);

            if (!hasValidNodes) {
                log.debug("❌ Bus {} has no valid station nodes for simulation", bus.getId());
                return false;
            }

            log.debug("✅ Bus {} can start simulation with {} nodes", bus.getId(), nodes.size());
            return true;

        } catch (Exception e) {
            log.error("❌ Error checking if bus {} can start simulation", bus.getId(), e);
            return false;
        }
    }

    private boolean isValidNode(RouteStationNode node) {
        try {
            return node != null &&
                    node.isActive() &&
                    node.getFromStation() != null &&
                    node.getFromStation().isActive() &&
                    !node.getFromStation().isDeleted() &&
                    node.getToStation() != null &&
                    node.getToStation().isActive() &&
                    !node.getToStation().isDeleted() &&
                    node.getFromStation().getLocation() != null &&
                    node.getToStation().getLocation() != null &&
                    isValidLocation(node.getFromStation().getLocation()) &&
                    isValidLocation(node.getToStation().getLocation());
        } catch (Exception e) {
            log.debug("❌ Error validating node {}: {}", node != null ? node.getId() : "null", e.getMessage());
            return false;
        }
    }

    private boolean isValidLocation(Location location) {
        return location != null &&
                Math.abs(location.getLatitude()) <= 90 &&
                Math.abs(location.getLongitude()) <= 180 &&
                location.getLatitude() != 0.0 &&
                location.getLongitude() != 0.0;
    }

    @Transactional(readOnly = true)
    public void startBusSimulation(Bus bus) {
        try {
            initializeExecutorService();

            Long busId = bus.getId();
            String plate = bus.getNumberPlate();

            if (runningSimulations.containsKey(busId)) {
                log.warn("⏱️ Simulation already running for bus: {} ({})", busId, plate);
                return;
            }

            if (!canStartSimulation(bus)) {
                throw new IllegalStateException("Bus is not suitable for simulation");
            }

            RouteDirection direction = bus.getCurrentDirection();
            List<RouteStationNode> nodes = direction.getStationNodes();

            // Enhanced preloading with validation
            List<RouteStationNode> validNodes = preloadAndValidateStationData(nodes);

            if (validNodes.isEmpty()) {
                throw new IllegalStateException("No valid nodes found after preloading");
            }

            // Create enhanced simulator task
            BusSimulatorTask task = new BusSimulatorTask(
                    bus,
                    validNodes,
                    restTemplate,
                    0,
                    updateIntervalSeconds,
                    this::onSimulationError
            );

            ScheduledFuture<?> future = executorService.scheduleWithFixedDelay(
                    () -> {
                        try {
                            task.run();
                        } catch (Exception e) {
                            log.error("❌ Error in simulation task for bus: {}", busId, e);
                            onSimulationError(busId, e);
                        }
                    },
                    0,
                    updateIntervalSeconds,
                    TimeUnit.SECONDS
            );

            // Store tracking information
            runningSimulations.put(busId, future);
            simulatorTasks.put(busId, task);
            simulationStartTimes.put(busId, LocalDateTime.now());
            errorCounts.put(busId, new AtomicInteger(0));

            log.info("✅ Started enhanced simulation for bus: {} ({}) on route: {} - Direction: {} - Valid Nodes: {}",
                    busId, plate, bus.getRouteDisplayName(), direction.getName(), validNodes.size());

        } catch (Exception e) {
            log.error("❌ Error while starting simulation for bus: {} ({})",
                    bus.getId(), bus.getNumberPlate() != null ? bus.getNumberPlate() : "N/A", e);
            throw new RuntimeException("Failed to start simulation for bus: " + bus.getId(), e);
        }
    }

    private List<RouteStationNode> preloadAndValidateStationData(List<RouteStationNode> nodes) {
        return nodes.stream()
                .filter(this::preloadAndValidateNode)
                .collect(Collectors.toList());
    }

    private boolean preloadAndValidateNode(RouteStationNode node) {
        try {
            if (node == null || !node.isActive()) {
                return false;
            }

            // Force loading and validation of station data
            Station fromStation = node.getFromStation();
            Station toStation = node.getToStation();

            if (!isValidStation(fromStation) || !isValidStation(toStation)) {
                return false;
            }

            // Force load location data
            Location fromLocation = fromStation.getLocation();
            Location toLocation = toStation.getLocation();

            if (!isValidLocation(fromLocation) || !isValidLocation(toLocation)) {
                return false;
            }

            // Force load all necessary fields
            fromStation.getName();
            toStation.getName();
            fromLocation.getLatitude();
            fromLocation.getLongitude();
            toLocation.getLatitude();
            toLocation.getLongitude();

            return true;

        } catch (Exception e) {
            log.warn("⚠️ Failed to preload/validate station data for node: {}",
                    node != null ? node.getId() : "null", e);
            return false;
        }
    }

    private boolean isValidStation(Station station) {
        return station != null &&
                station.isActive() &&
                !station.isDeleted() &&
                station.getLocation() != null;
    }

    @Transactional(readOnly = true)
    public void startBusSimulationById(Long busId) {
        Bus bus = busRepository.findByIdWithRoute(busId)
                .orElseThrow(() -> new RuntimeException("Bus not found: " + busId));

        if (!bus.isActive() || bus.isDeleted()) {
            throw new RuntimeException("Bus is not active or deleted: " + busId);
        }

        startBusSimulation(bus);
    }

    public void stopBusSimulation(Long busId) {
        ScheduledFuture<?> future = runningSimulations.remove(busId);
        BusSimulatorTask task = simulatorTasks.remove(busId);
        simulationStartTimes.remove(busId);
        errorCounts.remove(busId);

        if (future != null && !future.isCancelled()) {
            future.cancel(false);
            log.info("🛑 Stopped simulation for bus: {}", busId);
        } else {
            log.warn("⚠️ No running simulation found for bus: {}", busId);
        }
    }

    public void stopAllSimulations() {
        log.info("🛑 Stopping {} active simulations...", runningSimulations.size());

        runningSimulations.forEach((busId, future) -> {
            if (!future.isCancelled()) {
                future.cancel(false);
            }
        });

        runningSimulations.clear();
        simulatorTasks.clear();
        simulationStartTimes.clear();
        errorCounts.clear();

        log.info("✅ Stopped all bus simulations");
    }

    @Transactional(readOnly = true)
    public void restartBusSimulation(Long busId) {
        stopBusSimulation(busId);

        Bus bus = busRepository.findByIdWithRoute(busId)
                .orElseThrow(() -> new RuntimeException("Bus not found: " + busId));

        if (bus.isActive() && !bus.isDeleted()) {
            startBusSimulation(bus);
        }
    }

    public boolean isSimulationRunning(Long busId) {
        ScheduledFuture<?> future = runningSimulations.get(busId);
        return future != null && !future.isCancelled() && !future.isDone();
    }

    public int getActiveSimulationCount() {
        return (int) runningSimulations.values().stream()
                .filter(future -> !future.isCancelled() && !future.isDone())
                .count();
    }

    public Map<String, Object> getDetailedStatus() {
        Map<String, Object> status = new ConcurrentHashMap<>();
        status.put("activeSimulations", getActiveSimulationCount());
        status.put("totalSimulations", runningSimulations.size());
        status.put("simulationEnabled", true);
        status.put("initialized", initialized);
        status.put("shutdownRequested", shutdownRequested);
        status.put("threadPoolSize", threadPoolSize);
        status.put("updateInterval", updateIntervalSeconds);
        status.put("startTimes", simulationStartTimes);
        status.put("errorCounts", errorCounts.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().get()
                )));
        return status;
    }

    public BusSimulationStatus getSimulationStatus(Long busId) {
        BusSimulatorTask task = simulatorTasks.get(busId);
        boolean isRunning = isSimulationRunning(busId);
        LocalDateTime startTime = simulationStartTimes.get(busId);
        AtomicInteger errorCount = errorCounts.get(busId);

        if (task != null && isRunning) {
            return BusSimulationStatus.builder()
                    .busId(busId)
                    .isRunning(true)
                    .currentNodeIndex(task.getCurrentNodeIndex())
                    .currentProgress(task.getCurrentProgress())
                    .isAtStation(task.isAtStation())
                    .currentRouteSegment(task.getCurrentRouteSegment())
                    .startTime(startTime)
                    .errorCount(errorCount != null ? errorCount.get() : 0)
                    .lastUpdateTime(task.getLastUpdateTime())
                    .totalUpdates(task.getTotalUpdates())
                    .build();
        } else {
            return BusSimulationStatus.builder()
                    .busId(busId)
                    .isRunning(false)
                    .errorCount(errorCount != null ? errorCount.get() : 0)
                    .build();
        }
    }

    private void onSimulationError(Long busId, Exception error) {
        AtomicInteger errorCount = errorCounts.get(busId);
        if (errorCount != null) {
            int errors = errorCount.incrementAndGet();
            log.warn("⚠️ Simulation error for bus {} (error count: {}): {}",
                    busId, errors, error.getMessage());

            if (errors > 10) {
                log.error("❌ Too many errors for bus {}, stopping simulation", busId);
                stopBusSimulation(busId);
            }
        }
    }

    private void incrementErrorCount(Long busId) {
        errorCounts.computeIfAbsent(busId, k -> new AtomicInteger(0)).incrementAndGet();
    }

    // Enhanced status class with more details
    public static class BusSimulationStatus {
        private Long busId;
        private boolean isRunning;
        private int currentNodeIndex;
        private double currentProgress;
        private boolean isAtStation;
        private String currentRouteSegment;
        private LocalDateTime startTime;
        private LocalDateTime lastUpdateTime;
        private int errorCount;
        private long totalUpdates;

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private final BusSimulationStatus status = new BusSimulationStatus();

            public Builder busId(Long busId) {
                status.busId = busId;
                return this;
            }

            public Builder isRunning(boolean isRunning) {
                status.isRunning = isRunning;
                return this;
            }

            public Builder currentNodeIndex(int currentNodeIndex) {
                status.currentNodeIndex = currentNodeIndex;
                return this;
            }

            public Builder currentProgress(double currentProgress) {
                status.currentProgress = currentProgress;
                return this;
            }

            public Builder isAtStation(boolean isAtStation) {
                status.isAtStation = isAtStation;
                return this;
            }

            public Builder currentRouteSegment(String currentRouteSegment) {
                status.currentRouteSegment = currentRouteSegment;
                return this;
            }

            public Builder startTime(LocalDateTime startTime) {
                status.startTime = startTime;
                return this;
            }

            public Builder lastUpdateTime(LocalDateTime lastUpdateTime) {
                status.lastUpdateTime = lastUpdateTime;
                return this;
            }

            public Builder errorCount(int errorCount) {
                status.errorCount = errorCount;
                return this;
            }

            public Builder totalUpdates(long totalUpdates) {
                status.totalUpdates = totalUpdates;
                return this;
            }

            public BusSimulationStatus build() {
                return status;
            }
        }

        // Getters
        public Long getBusId() {
            return busId;
        }

        public boolean isRunning() {
            return isRunning;
        }

        public int getCurrentNodeIndex() {
            return currentNodeIndex;
        }

        public double getCurrentProgress() {
            return currentProgress;
        }

        public boolean isAtStation() {
            return isAtStation;
        }

        public String getCurrentRouteSegment() {
            return currentRouteSegment;
        }

        public LocalDateTime getStartTime() {
            return startTime;
        }

        public LocalDateTime getLastUpdateTime() {
            return lastUpdateTime;
        }

        public int getErrorCount() {
            return errorCount;
        }

        public long getTotalUpdates() {
            return totalUpdates;
        }
    }
}