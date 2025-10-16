package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.UserFavoriteCard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserFavoriteCardRepository extends JpaRepository<UserFavoriteCard, Long> {

}