package akin.city_card.buscard.repository;


import akin.city_card.buscard.model.BusCard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BusCardRepository extends JpaRepository<BusCard, Long> {
    @Query(value = "SELECT * FROM bus_card WHERE TRIM(card_number) = TRIM(:uid)", nativeQuery = true)
    Optional<BusCard> findByCardNumberNative(@Param("uid") String uid);

    boolean existsByCardNumber(String uid);

}
