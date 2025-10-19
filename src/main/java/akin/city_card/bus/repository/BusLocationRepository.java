package akin.city_card.bus.repository;

import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusLocation;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface BusLocationRepository extends JpaRepository<BusLocation, Long> {
    Optional<BusLocation> findTopByBusOrderByTimestampDesc(Bus bus);

    List<BusLocation> findAllByBusAndTimestampBetweenOrderByTimestampDesc(Bus bus, LocalDateTime startOfDay, LocalDateTime endOfDay);


    List<BusLocation> findAllByBusAndTimestampAfterOrderByTimestampDesc(Bus bus, LocalDateTime yesterday);

    Page<BusLocation> findAllByBusAndTimestampBetween(
            Bus bus,
            LocalDateTime start,
            LocalDateTime end,
            Pageable pageable
    );
}
