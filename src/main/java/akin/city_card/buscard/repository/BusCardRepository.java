package akin.city_card.buscard.repository;

import akin.city_card.bus.model.Bus;
import akin.city_card.buscard.model.BusCard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BusCardRepository extends JpaRepository<BusCard, Long>, JpaSpecificationExecutor<BusCard> {

    Optional<BusCard> findByCardNumber(String uid);

    boolean existsByCardNumber(String uid);

}
