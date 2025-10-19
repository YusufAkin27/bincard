package akin.city_card.simulation;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.bus.model.Bus;
import akin.city_card.route.model.RouteDirection;
import akin.city_card.route.model.RouteStationNode;
import akin.city_card.station.model.Station;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BiConsumer;

@Slf4j
public class BusSimulatorTask implements Runnable {

    private final Bus bus;
    private List<RouteStationNode> currentRouteNodes;
    private final RestTemplate restTemplate;
    private final int updateIntervalSeconds;
    private final BiConsumer<Long, Exception> errorCallback;

    // Movement state
    private volatile int currentNodeIndex = 0;
    private volatile double currentProgress = 0.0; // 0.0 to 1.0 between stations
    private volatile boolean isAtStation = false;
    private volatile LocalDateTime stationArrivalTime;
    private volatile LocalDateTime lastUpdateTime;
    private volatile boolean isDirectionSwitched = false;
    private final AtomicLong totalUpdates = new AtomicLong(0);
    private final AtomicLong successfulUpdates = new AtomicLong(0);

    // Enhanced speed configuration (km/h)
    private static final double MIN_SPEED_KMH = 25.0;
    private static final double MAX_SPEED_KMH = 45.0;
    private static final double STATION_STOP_DURATION_MINUTES = 0.5; // 30 seconds
    private static final double TRAFFIC_LIGHT_STOP_PROBABILITY = 0.15; // 15% chance
    private static final double TRAFFIC_LIGHT_STOP_DURATION_SECONDS = 30.0;

    // Enhanced randomization and realism
    private final Random random = new Random();
    private static final double SPEED_VARIATION = 0.20; // ±20% speed variation
    private static final double POSITION_NOISE = 0.000008; // Slightly more GPS noise for realism
    private static final double ACCELERATION_FACTOR = 0.05; // Gradual speed changes

    // Traffic simulation
    private LocalDateTime trafficStopEndTime;
    private double currentSpeedKmh;
    private boolean isAccelerating = true;

    // Performance tracking
    private LocalDateTime lastSuccessfulUpdate;
    private int consecutiveErrors = 0;
    private static final int MAX_CONSECUTIVE_ERRORS = 5;

    public BusSimulatorTask(Bus bus, List<RouteStationNode> routeNodes,
                            RestTemplate restTemplate, double speedKmh, int updateIntervalSeconds,
                            BiConsumer<Long, Exception> errorCallback) {
        this.bus = bus;
        this.restTemplate = restTemplate;
        this.updateIntervalSeconds = updateIntervalSeconds;
        this.errorCallback = errorCallback;
        this.lastUpdateTime = LocalDateTime.now();
        this.lastSuccessfulUpdate = LocalDateTime.now();

        // Initialize with current direction
        initializeRoute(bus.getCurrentDirection());

        if (!this.currentRouteNodes.isEmpty()) {
            // Start from a random position for variety
            this.currentNodeIndex = random.nextInt(this.currentRouteNodes.size());
            this.currentProgress = random.nextDouble() * 0.2; // Start closer to beginning of segment
            this.currentSpeedKmh = MIN_SPEED_KMH + random.nextDouble() * (MAX_SPEED_KMH - MIN_SPEED_KMH);

            log.info("🚌 Initialized enhanced bus {} simulation with {} nodes, starting at node {} with speed {:.1f} km/h",
                    bus.getId(), this.currentRouteNodes.size(), currentNodeIndex, currentSpeedKmh);
        } else {
            log.warn("⚠️ No valid route nodes found for bus {}", bus.getId());
        }
    }

    private void initializeRoute(RouteDirection direction) {
        if (direction == null || direction.getStationNodes() == null) {
            this.currentRouteNodes = List.of();
            log.warn("❌ No route direction or nodes found for bus: {}", bus.getId());
            return;
        }

        this.currentRouteNodes = direction.getStationNodes().stream()
                .filter(this::isValidRouteNode)
                .sorted(Comparator.comparingInt(RouteStationNode::getSequenceOrder))
                .toList();

        log.debug("✅ Loaded {} valid route nodes for direction: {} (bus {})",
                this.currentRouteNodes.size(), direction.getName(), bus.getId());
    }

    private boolean isValidRouteNode(RouteStationNode node) {
        try {
            return node != null &&
                    node.isActive() &&
                    node.getFromStation() != null &&
                    node.getToStation() != null &&
                    node.getFromStation().getLocation() != null &&
                    node.getToStation().getLocation() != null &&
                    node.getFromStation().isActive() &&
                    node.getToStation().isActive() &&
                    !node.getFromStation().isDeleted() &&
                    !node.getToStation().isDeleted() &&
                    isValidCoordinate(node.getFromStation().getLocation().getLatitude()) &&
                    isValidCoordinate(node.getFromStation().getLocation().getLongitude()) &&
                    isValidCoordinate(node.getToStation().getLocation().getLatitude()) &&
                    isValidCoordinate(node.getToStation().getLocation().getLongitude());
        } catch (Exception e) {
            log.debug("❌ Invalid route node for bus {}: {}", bus.getId(), e.getMessage());
            return false;
        }
    }

    private boolean isValidCoordinate(Double coordinate) {
        return coordinate != null &&
                coordinate != 0.0 &&
                Math.abs(coordinate) <= 180 &&
                !coordinate.isNaN() &&
                !coordinate.isInfinite();
    }

    @Override
    public void run() {
        long updateCount = totalUpdates.incrementAndGet();
        lastUpdateTime = LocalDateTime.now();

        try {
            if (currentRouteNodes.isEmpty()) {
                log.warn("⚠️ No route nodes available for bus: {} (update #{})", bus.getId(), updateCount);
                handleError(new IllegalStateException("No route nodes available"));
                return;
            }

            simulateRealisticMovement();
            successfulUpdates.incrementAndGet();
            consecutiveErrors = 0; // Reset error count on success
            lastSuccessfulUpdate = LocalDateTime.now();

        } catch (Exception e) {
            consecutiveErrors++;
            log.error("❌ Error in enhanced simulation task for bus: {} (update #{}, consecutive errors: {})",
                    bus.getId(), updateCount, consecutiveErrors, e);

            if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                log.error("🚨 Too many consecutive errors for bus {}, stopping simulation", bus.getId());
            }

            handleError(e);
        }
    }

    private void simulateRealisticMovement() {
        // Check if we're stopped at traffic light
        if (isStoppedAtTrafficLight()) {
            sendLocationUpdate(getCurrentPosition(), 0.0); // Speed 0 when stopped
            return;
        }

        // Check if we're at a station and need to wait
        if (isAtStation) {
            handleStationStop();
            return;
        }

        RouteStationNode currentNode = getCurrentNode();
        if (currentNode == null) {
            log.error("❌ Current node is null for bus: {} at index {}", bus.getId(), currentNodeIndex);
            moveToNextNode();
            return;
        }

        Station fromStation = currentNode.getFromStation();
        Station toStation = currentNode.getToStation();

        if (!isValidStationPair(fromStation, toStation)) {
            log.warn("⚠️ Invalid station data for bus: {} at node: {}", bus.getId(), currentNodeIndex);
            moveToNextNode();
            return;
        }

        // Simulate realistic speed changes
        adjustSpeed();

        // Check for random traffic light stops
        checkForTrafficLight();

        // Calculate and send current position
        double[] currentPosition = calculateCurrentPosition(fromStation, toStation, currentProgress);
        double lat = addGPSNoise(currentPosition[0]);
        double lon = addGPSNoise(currentPosition[1]);

        sendLocationUpdate(new double[]{lat, lon}, currentSpeedKmh);

        // Update movement progress
        updateMovementProgress(fromStation, toStation);
    }

    private boolean isStoppedAtTrafficLight() {
        if (trafficStopEndTime != null) {
            LocalDateTime now = LocalDateTime.now();
            if (now.isBefore(trafficStopEndTime)) {
                return true; // Still stopped
            } else {
                trafficStopEndTime = null; // Resume movement
                isAccelerating = true; // Start accelerating again
                log.debug("🚦 Bus {} resuming after traffic light", bus.getId());
                return false;
            }
        }
        return false;
    }

    private void checkForTrafficLight() {
        if (trafficStopEndTime == null && random.nextDouble() < TRAFFIC_LIGHT_STOP_PROBABILITY / 100.0) {
            // Stop at traffic light
            trafficStopEndTime = LocalDateTime.now().plusSeconds((long) TRAFFIC_LIGHT_STOP_DURATION_SECONDS);
            currentSpeedKmh = 0.0;
            log.debug("🚦 Bus {} stopped at traffic light for {} seconds", bus.getId(), TRAFFIC_LIGHT_STOP_DURATION_SECONDS);
        }
    }

    private void adjustSpeed() {
        if (isAccelerating) {
            // Gradually increase speed
            double targetSpeed = MIN_SPEED_KMH + random.nextDouble() * (MAX_SPEED_KMH - MIN_SPEED_KMH);
            currentSpeedKmh = Math.min(currentSpeedKmh + (ACCELERATION_FACTOR * targetSpeed), targetSpeed);

            if (Math.abs(currentSpeedKmh - targetSpeed) < 1.0) {
                isAccelerating = false; // Reached target speed
            }
        } else {
            // Add natural speed variation
            double variation = (random.nextGaussian() * SPEED_VARIATION * currentSpeedKmh);
            currentSpeedKmh = Math.max(MIN_SPEED_KMH * 0.8,
                    Math.min(MAX_SPEED_KMH * 1.1, currentSpeedKmh + variation));
        }
    }

    private double addGPSNoise(double coordinate) {
        return coordinate + (random.nextGaussian() * POSITION_NOISE);
    }

    private double[] getCurrentPosition() {
        RouteStationNode currentNode = getCurrentNode();
        if (currentNode == null) return new double[]{0.0, 0.0};

        Station fromStation = currentNode.getFromStation();
        Station toStation = currentNode.getToStation();

        if (!isValidStationPair(fromStation, toStation)) {
            return new double[]{0.0, 0.0};
        }

        return calculateCurrentPosition(fromStation, toStation, currentProgress);
    }

    private void handleStationStop() {
        if (stationArrivalTime == null) {
            stationArrivalTime = LocalDateTime.now();
            currentSpeedKmh = 0.0; // Bus stops at station

            RouteStationNode currentNode = getCurrentNode();
            String stationName = currentNode != null && currentNode.getToStation() != null ?
                    currentNode.getToStation().getName() : "Unknown";

            log.debug("🚏 Bus {} arrived at station: {} (stopping for {:.1f} minutes)",
                    bus.getId(), stationName, STATION_STOP_DURATION_MINUTES);
            return;
        }

        // Check if stop duration has passed
        LocalDateTime now = LocalDateTime.now();
        double minutesSinceArrival = java.time.Duration.between(stationArrivalTime, now).toSeconds() / 60.0;

        if (minutesSinceArrival >= STATION_STOP_DURATION_MINUTES) {
            // Resume movement
            isAtStation = false;
            stationArrivalTime = null;
            isAccelerating = true; // Start accelerating from station
            currentSpeedKmh = MIN_SPEED_KMH * 0.3; // Start slow from station

            moveToNextNode();

            RouteStationNode nextNode = getCurrentNode();
            String nextStationName = nextNode != null && nextNode.getToStation() != null ?
                    nextNode.getToStation().getName() : "Unknown";

            log.debug("🚌 Bus {} departing from station towards: {}", bus.getId(), nextStationName);
        } else {
            // Still at station, send current position with speed 0
            double[] position = getCurrentPosition();
            sendLocationUpdate(position, 0.0);
        }
    }

    private RouteStationNode getCurrentNode() {
        if (currentNodeIndex >= 0 && currentNodeIndex < currentRouteNodes.size()) {
            return currentRouteNodes.get(currentNodeIndex);
        }
        return null;
    }

    private boolean isValidStationPair(Station from, Station to) {
        return from != null && to != null &&
                from.getLocation() != null && to.getLocation() != null &&
                from.isActive() && to.isActive() &&
                !from.isDeleted() && !to.isDeleted() &&
                isValidCoordinate(from.getLocation().getLatitude()) &&
                isValidCoordinate(from.getLocation().getLongitude()) &&
                isValidCoordinate(to.getLocation().getLatitude()) &&
                isValidCoordinate(to.getLocation().getLongitude());
    }

    private double[] calculateCurrentPosition(Station from, Station to, double progress) {
        double fromLat = from.getLocation().getLatitude();
        double fromLon = from.getLocation().getLongitude();
        double toLat = to.getLocation().getLatitude();
        double toLon = to.getLocation().getLongitude();

        // Enhanced interpolation with curve simulation for more realistic movement
        double curveOffset = Math.sin(progress * Math.PI) * 0.0001; // Small curve for realism

        double currentLat = fromLat + progress * (toLat - fromLat) + curveOffset;
        double currentLon = fromLon + progress * (toLon - fromLon) + curveOffset;

        return new double[]{currentLat, currentLon};
    }

    private void updateMovementProgress(Station from, Station to) {
        // Calculate distance between stations
        double distanceKm = haversine(
                from.getLocation().getLatitude(), from.getLocation().getLongitude(),
                to.getLocation().getLatitude(), to.getLocation().getLongitude()
        );

        // If distance is very small, immediately move to next station
        if (distanceKm < 0.005) { // 5 meters
            arrivedAtStation();
            return;
        }

        // Calculate progress based on current speed and time
        double timeHours = updateIntervalSeconds / 3600.0;
        double distanceTraveled = currentSpeedKmh * timeHours;
        double progressIncrement = distanceTraveled / distanceKm;

        // Add some randomness for traffic conditions
        double trafficFactor = 0.8 + (random.nextDouble() * 0.4); // 0.8 to 1.2 variation
        progressIncrement *= trafficFactor;

        currentProgress += progressIncrement;

        // Check if we've reached the destination station
        if (currentProgress >= 1.0) {
            arrivedAtStation();
        }
    }

    private void arrivedAtStation() {
        currentProgress = 1.0; // Ensure we're exactly at the station
        isAtStation = true;
        stationArrivalTime = null; // Will be set in handleStationStop()

        RouteStationNode currentNode = getCurrentNode();
        if (currentNode != null) {
            log.debug("🚏 Bus {} arrived at station: {} -> {}",
                    bus.getId(),
                    currentNode.getFromStation().getName(),
                    currentNode.getToStation().getName());
        }
    }

    private void moveToNextNode() {
        currentProgress = 0.0;
        currentNodeIndex++;

        // Check if we've reached the end of current route
        if (currentNodeIndex >= currentRouteNodes.size()) {
            switchDirection();
        }

        if (currentNodeIndex < currentRouteNodes.size()) {
            RouteStationNode nextNode = currentRouteNodes.get(currentNodeIndex);
            log.debug("➡️ Bus {} moving to next segment: {} -> {} (node {}/{})",
                    bus.getId(),
                    nextNode.getFromStation().getName(),
                    nextNode.getToStation().getName(),
                    currentNodeIndex + 1,
                    currentRouteNodes.size());
        }
    }

    private void switchDirection() {
        try {
            log.info("🔄 Bus {} reached end of route, switching direction", bus.getId());

            // Switch direction in the bus entity
            if (bus.getAssignedRoute() != null) {
                RouteDirection currentDirection = bus.getCurrentDirection();
                RouteDirection newDirection;

                if (currentDirection.equals(bus.getAssignedRoute().getOutgoingDirection())) {
                    newDirection = bus.getAssignedRoute().getReturnDirection();
                } else {
                    newDirection = bus.getAssignedRoute().getOutgoingDirection();
                }

                if (newDirection != null && !newDirection.getStationNodes().isEmpty()) {
                    // Update bus direction
                    bus.setCurrentDirection(newDirection);

                    // Reinitialize route with new direction
                    initializeRoute(newDirection);
                    currentNodeIndex = 0;
                    currentProgress = 0.0;
                    isDirectionSwitched = true;
                    isAccelerating = true; // Start accelerating in new direction

                    log.info("✅ Bus {} switched to direction: {} with {} nodes",
                            bus.getId(), newDirection.getName(), currentRouteNodes.size());
                } else {
                    log.error("❌ Could not find valid return direction for bus: {}", bus.getId());
                    currentNodeIndex = 0; // Reset to beginning
                }
            }
        } catch (Exception e) {
            log.error("❌ Error switching direction for bus: {}", bus.getId(), e);
            currentNodeIndex = 0; // Reset to beginning as fallback
        }
    }

    private void sendLocationUpdate(double[] position, double speed) {
        try {
            if (position == null || position.length < 2) {
                log.warn("⚠️ Invalid position for bus {}", bus.getId());
                return;
            }

            UpdateLocationRequest requestBody = new UpdateLocationRequest();
            requestBody.setLatitude(position[0]);
            requestBody.setLongitude(position[1]);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("User-Agent", "BusSimulator/2.0");
            HttpEntity<UpdateLocationRequest> entity = new HttpEntity<>(requestBody, headers);

            String url = "http://localhost:8080/v1/api/bus/" + bus.getId() + "/location";

            restTemplate.postForEntity(url, entity, Void.class);

            if (log.isDebugEnabled()) {
                RouteStationNode currentNode = getCurrentNode();
                String routeInfo = currentNode != null ?
                        String.format("%s -> %s",
                                currentNode.getFromStation().getName(),
                                currentNode.getToStation().getName()) : "Unknown";

                log.debug("📍 Bus {} location updated - Lat: {}, Lon: {}, Speed: {:.1f} km/h, Progress: {:.1f}%, Route: {}, Updates: {}",
                        bus.getId(),
                        String.format("%.6f", position[0]),
                        String.format("%.6f", position[1]),
                        speed,
                        currentProgress * 100,
                        routeInfo,
                        totalUpdates.get());
            }

        } catch (Exception e) {
            log.error("❌ Failed to send location update for bus: {} (attempt #{})", bus.getId(), totalUpdates.get(), e);
            handleError(e);
        }
    }

    private void handleError(Exception e) {
        if (errorCallback != null) {
            errorCallback.accept(bus.getId(), e);
        }
    }

    /**
     * Calculate distance between two points using Haversine formula
     */
    private double haversine(double lat1, double lon1, double lat2, double lon2) {
        final double R = 6371.0; // Earth radius in kilometers

        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);

        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
                        Math.sin(dLon / 2) * Math.sin(dLon / 2);

        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

        return R * c;
    }

    // Enhanced getters with additional information
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
        RouteStationNode currentNode = getCurrentNode();
        if (currentNode != null && currentNode.getFromStation() != null && currentNode.getToStation() != null) {
            return currentNode.getFromStation().getName() + " -> " + currentNode.getToStation().getName();
        }
        return "Unknown Route";
    }

    public LocalDateTime getLastUpdateTime() {
        return lastUpdateTime;
    }

    public long getTotalUpdates() {
        return totalUpdates.get();
    }

    public long getSuccessfulUpdates() {
        return successfulUpdates.get();
    }

    public double getCurrentSpeedKmh() {
        return currentSpeedKmh;
    }

    public boolean isDirectionSwitched() {
        return isDirectionSwitched;
    }

    public LocalDateTime getLastSuccessfulUpdate() {
        return lastSuccessfulUpdate;
    }

    public int getConsecutiveErrors() {
        return consecutiveErrors;
    }

    public boolean isHealthy() {
        return consecutiveErrors < MAX_CONSECUTIVE_ERRORS &&
                lastSuccessfulUpdate.isAfter(LocalDateTime.now().minusMinutes(5));
    }
}