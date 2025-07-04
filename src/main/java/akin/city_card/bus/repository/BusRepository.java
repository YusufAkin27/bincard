package akin.city_card.bus.repository;

import akin.city_card.bus.model.Bus;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BusRepository extends JpaRepository<Bus, Long> {
    boolean existsByNumberPlate(String numberPlate);
}
