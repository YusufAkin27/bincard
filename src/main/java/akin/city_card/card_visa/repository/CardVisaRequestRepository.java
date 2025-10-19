package akin.city_card.card_visa.repository;

import akin.city_card.card_visa.model.CardVisaRequest;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CardVisaRequestRepository extends JpaRepository<CardVisaRequest, Long> {
}
