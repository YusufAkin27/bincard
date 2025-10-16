package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.BusCard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface BusCardRepository extends JpaRepository<BusCard, Long>, JpaSpecificationExecutor<BusCard> {

    BusCard findByCardNumber(String uid);
}
