package akin.city_card.bus.repository;

import akin.city_card.bus.model.BusRide;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BusRideRepository extends JpaRepository<BusRide,Long> {
}
