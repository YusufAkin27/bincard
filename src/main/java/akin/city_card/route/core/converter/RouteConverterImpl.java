package akin.city_card.route.core.converter;

import akin.city_card.bus.core.converter.BusConverter;
import akin.city_card.route.core.response.*;
import akin.city_card.route.model.*;
import akin.city_card.station.core.converter.StationConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class RouteConverterImpl implements RouteConverter {
    private final BusConverter busConverter;
    private final StationConverter stationConverter;

    /**
     * Route -> RouteDTO dönüşümü
     */
    @Override
    public RouteDTO toRouteDTO(Route route) {
        if (route == null) return null;

        return RouteDTO.builder()
                .id(route.getId())
                .name(route.getName())
                .code(route.getCode())
                .description(route.getDescription())
                .routeType(route.getRouteType() != null ? route.getRouteType().getDisplayName() : null)
                .color(route.getColor())
                .createdAt(route.getCreatedAt())
                .updatedAt(route.getUpdatedAt())
                .isActive(route.isActive())
                .isDeleted(route.isDeleted())
                .startStation(stationConverter.toDTO(route.getStartStation()))
                .endStation(stationConverter.toDTO(route.getEndStation()))
                .estimatedDurationMinutes(route.getEstimatedDurationMinutes())
                .totalDistanceKm(route.getTotalDistanceKm())
                .schedule(toRouteScheduleDTO(route.getSchedule()))
                .directions(route.getDirections() != null ?
                        route.getDirections().stream()
                                .map(this::toRouteDirectionDTO)
                                .collect(Collectors.toList()) : null)
                .build();
    }

    /**
     * Route -> RouteNameDTO dönüşümü
     */
    @Override
    public RouteNameDTO toRouteNameDTO(Route route) {
        if (route == null) return null;

        return RouteNameDTO.builder()
                .id(route.getId())
                .name(route.getName())
                .code(route.getCode())
                .routeType(route.getRouteType() != null ? route.getRouteType().getDisplayName() : null)
                .color(route.getColor())
                .startStationName(route.getStartStation() != null ? route.getStartStation().getName() : null)
                .endStationName(route.getEndStation() != null ? route.getEndStation().getName() : null)
                .estimatedDurationMinutes(route.getEstimatedDurationMinutes())
                .totalDistanceKm(route.getTotalDistanceKm())
                .routeSchedule(toRouteScheduleDTO(route.getSchedule()))
                .hasOutgoingDirection(route.getDirections() != null &&
                        route.getDirections().stream().anyMatch(d -> d.getType() == DirectionType.GIDIS))
                .hasReturnDirection(route.getDirections() != null &&
                        route.getDirections().stream().anyMatch(d -> d.getType() == DirectionType.DONUS))
                .build();
    }

    /**
     * RouteDirection -> RouteDirectionDTO dönüşümü
     */
    @Override
    public RouteDirectionDTO toRouteDirectionDTO(RouteDirection direction) {
        if (direction == null) return null;

        return RouteDirectionDTO.builder()
                .id(direction.getId())
                .name(direction.getName())
                .type(direction.getType())
                .startStation(stationConverter.toDTO(direction.getStartStation()))
                .endStation(stationConverter.toDTO(direction.getEndStation()))
                .estimatedDurationMinutes(direction.getEstimatedDurationMinutes())
                .totalDistanceKm(direction.getTotalDistanceKm())
                .isActive(direction.isActive())
                .stationNodes(direction.getStationNodes() != null ?
                        direction.getStationNodes().stream()
                                .sorted((a, b) -> Integer.compare(a.getSequenceOrder(), b.getSequenceOrder()))
                                .map(this::toRouteStationNodeDTO)
                                .collect(Collectors.toList()) : null)
                .totalStationCount(direction.getTotalStationCount())
                .build();
    }

    /**
     * RouteStationNode -> RouteStationNodeDTO dönüşümü
     */
    public RouteStationNodeDTO toRouteStationNodeDTO(RouteStationNode node) {
        if (node == null) return null;

        return RouteStationNodeDTO.builder()
                .id(node.getId())
                .fromStation(stationConverter.toDTO(node.getFromStation()))
                .toStation(stationConverter.toDTO(node.getToStation()))
                .sequenceOrder(node.getSequenceOrder())
                .estimatedTravelTimeMinutes(node.getEstimatedTravelTimeMinutes())
                .distanceKm(node.getDistanceKm())
                .isActive(node.isActive())
                .notes(node.getNotes())
                .build();
    }

    /**
     * RouteSchedule -> RouteScheduleDTO dönüşümü
     */
    public RouteScheduleDTO toRouteScheduleDTO(RouteSchedule schedule) {
        if (schedule == null) return null;

        return RouteScheduleDTO.builder()
                .weekdayHours(schedule.getWeekdayHours())
                .weekendHours(schedule.getWeekendHours())
                .build();
    }

    /**
     * Route listesi -> RouteNameDTO listesi dönüşümü
     */
    public List<RouteNameDTO> toRouteNameDTOList(List<Route> routes) {
        if (routes == null) return null;

        return routes.stream()
                .map(this::toRouteNameDTO)
                .collect(Collectors.toList());
    }

    /**
     * RouteDirection listesi -> RouteDirectionDTO listesi dönüşümü
     */
    public List<RouteDirectionDTO> toRouteDirectionDTOList(List<RouteDirection> directions) {
        if (directions == null) return null;

        return directions.stream()
                .map(this::toRouteDirectionDTO)
                .collect(Collectors.toList());
    }

    /**
     * Route -> PublicRouteDTO dönüşümü (genel kullanım için)
     */
    public PublicRouteDTO toPublicRouteDTO(Route route) {
        if (route == null) return null;

        return PublicRouteDTO.builder()
                .id(route.getId())
                .name(route.getName())
                .startStation(stationConverter.toDTO(route.getStartStation()))
                .endStation(stationConverter.toDTO(route.getEndStation()))
                .build();
    }

    /**
     * TimeSlot enum'unu string'e çevirme
     */
    public String timeSlotToString(TimeSlot timeSlot) {
        return timeSlot != null ? timeSlot.toHourMinute() : null;
    }

    /**
     * DirectionType enum'unu displayName'e çevirme
     */
    public String directionTypeToString(DirectionType directionType) {
        if (directionType == null) return null;

        return switch (directionType) {
            case GIDIS -> "Gidiş";
            case DONUS -> "Dönüş";
        };
    }

    @Override
    public PublicRouteDTO toPublicRoute(Route route) {
        return PublicRouteDTO.builder()
                .startStation(stationConverter.toDTO(route.getStartStation()))
                .endStation(stationConverter.toDTO(route.getEndStation()))
                .id(route.getId())
                .name(route.getName())
                .build();

    }

    /**
     * RouteType enum'unu displayName'e çevirme
     */
    public String routeTypeToString(RouteType routeType) {
        return routeType != null ? routeType.getDisplayName() : null;
    }

    /**
     * Mesafe formatlaması (km veya m olarak)
     */
    public String formatDistance(Double distanceKm) {
        if (distanceKm == null) return null;

        if (distanceKm < 1.0) {
            return String.format("%.0f m", distanceKm * 1000);
        } else {
            return String.format("%.1f km", distanceKm);
        }
    }

    /**
     * Süre formatlaması (dakika veya saat olarak)
     */
    public String formatDuration(Integer minutes) {
        if (minutes == null) return null;

        if (minutes < 60) {
            return minutes + " dk";
        } else {
            int hours = minutes / 60;
            int remainingMinutes = minutes % 60;
            if (remainingMinutes == 0) {
                return hours + " sa";
            } else {
                return hours + " sa " + remainingMinutes + " dk";
            }
        }
    }

    /**
     * Rota durumu kontrolü
     */
    public boolean isRouteOperational(Route route) {
        return route != null && route.isActive() && !route.isDeleted() &&
                route.getDirections() != null && !route.getDirections().isEmpty() &&
                route.getDirections().stream().anyMatch(RouteDirection::isActive);
    }

    /**
     * Rota yönü durumu kontrolü
     */
    public boolean isDirectionOperational(RouteDirection direction) {
        return direction != null && direction.isActive() &&
                direction.getStationNodes() != null && !direction.getStationNodes().isEmpty() &&
                direction.getStationNodes().stream().anyMatch(RouteStationNode::isActive);
    }

    /**
     * Toplam aktif durak sayısını hesaplama
     */
    public int countActiveStations(RouteDirection direction) {
        if (direction == null || direction.getStationNodes() == null) return 0;

        // Başlangıç durağı + aktif node'ların hedef durakları
        return 1 + (int) direction.getStationNodes().stream()
                .filter(RouteStationNode::isActive)
                .count();
    }

    /**
     * Rota kodunu formatla (boşsa ID kullan)
     */
    public String formatRouteCode(Route route) {
        if (route == null) return null;

        if (route.getCode() != null && !route.getCode().trim().isEmpty()) {
            return route.getCode();
        } else {
            return "R" + route.getId(); // Fallback olarak R + ID
        }
    }

    /**
     * Rota adını formatla (başlangıç - bitiş formatında)
     */
    public String formatRouteName(Route route) {
        if (route == null) return null;

        if (route.getName() != null && !route.getName().trim().isEmpty()) {
            return route.getName();
        } else {
            // Fallback olarak başlangıç - bitiş durağı adları
            String start = route.getStartStation() != null ? route.getStartStation().getName() : "Bilinmeyen";
            String end = route.getEndStation() != null ? route.getEndStation().getName() : "Bilinmeyen";
            return start + " - " + end;
        }
    }

    /**
     * Yön adını formatla
     */
    public String formatDirectionName(RouteDirection direction) {
        if (direction == null) return null;

        if (direction.getName() != null && !direction.getName().trim().isEmpty()) {
            return direction.getName();
        } else {
            // Fallback olarak tip + başlangıç → bitiş
            String typeStr = directionTypeToString(direction.getType());
            String start = direction.getStartStation() != null ? direction.getStartStation().getName() : "Bilinmeyen";
            String end = direction.getEndStation() != null ? direction.getEndStation().getName() : "Bilinmeyen";
            return typeStr + ": " + start + " → " + end;
        }
    }

    /**
     * Rota özet bilgisi (kısa açıklama)
     */
    public String createRouteSummary(Route route) {
        if (route == null) return null;

        StringBuilder summary = new StringBuilder();
        summary.append(formatRouteCode(route));

        if (route.getRouteType() != null) {
            summary.append(" (").append(route.getRouteType().getDisplayName()).append(")");
        }

        if (route.getEstimatedDurationMinutes() != null) {
            summary.append(" - ").append(formatDuration(route.getEstimatedDurationMinutes()));
        }

        if (route.getTotalDistanceKm() != null) {
            summary.append(" - ").append(formatDistance(route.getTotalDistanceKm()));
        }

        return summary.toString();
    }
}
