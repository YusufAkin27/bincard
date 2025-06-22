package akin.city_card.user.repository;

import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUserNumber(String username) throws UserNotFoundException;

    boolean existsByUserNumber(String telephone);

    boolean existsByEmail(String email);

    boolean existsByNationalId(String nationalId);
}
