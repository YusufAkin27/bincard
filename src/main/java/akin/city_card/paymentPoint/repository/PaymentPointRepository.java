package akin.city_card.paymentPoint.repository;

import akin.city_card.paymentPoint.model.PaymentPoint;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentPointRepository extends JpaRepository<PaymentPoint, Long> {
}
