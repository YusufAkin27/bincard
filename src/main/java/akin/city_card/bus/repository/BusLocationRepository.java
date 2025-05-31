package akin.city_card.bus.repository;

import akin.city_card.bus.model.BusLocation;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BusLocationRepository extends JpaRepository<BusLocation, Long> {
}
