package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.BusCardActivity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ActivityRepository extends JpaRepository<BusCardActivity, Long> {
}
