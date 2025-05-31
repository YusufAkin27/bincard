package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.Card;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CardRepository extends JpaRepository<Card, Long> {
}
