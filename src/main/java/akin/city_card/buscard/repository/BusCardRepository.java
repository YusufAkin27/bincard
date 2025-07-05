package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.BusCard;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BusCardRepository extends JpaRepository<BusCard, Long> {
}
