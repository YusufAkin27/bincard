package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.CardPricing;
import akin.city_card.buscard.model.CardType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CardPricingRepository extends JpaRepository<CardPricing, Long> {

    Optional<CardPricing> findByCardType(CardType type);

}