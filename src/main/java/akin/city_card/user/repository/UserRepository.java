package akin.city_card.user.repository;

import akin.city_card.buscard.model.UserFavoriteCard;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUserNumber(String username) throws UserNotFoundException;

    boolean existsByNationalId(String nationalId);


    @Query("""
       SELECT u FROM User u
       WHERE LOWER(u.nationalId) LIKE %:query%
          OR LOWER(u.userNumber) LIKE %:query%
          OR LOWER(u.profileInfo.email) LIKE %:query%
          OR LOWER(u.profileInfo.name) LIKE %:query%
          OR LOWER(u.profileInfo.surname) LIKE %:query%
       """)
    Page<User> searchByQuery(@Param("query") String query, Pageable pageable);

    @Query("SELECT ufc FROM UserFavoriteCard ufc WHERE ufc.user.userNumber = :username")
    List<UserFavoriteCard> findFavoriteCardsByUserNumber(@Param("username") String username);
}
