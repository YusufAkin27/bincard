package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.CardStatus;
import akin.city_card.buscard.model.CardType;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Repository
public interface BusCardRepository extends JpaRepository<BusCard, Long>, JpaSpecificationExecutor<BusCard> {

}
