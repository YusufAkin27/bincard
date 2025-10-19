package akin.city_card.security.repository;

import akin.city_card.security.entity.SecurityUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SecurityUserRepository extends JpaRepository<SecurityUser, Long> {
    Optional<SecurityUser> findByUserNumber(String userNumber); // Kullanıcı numarasına göre kullanıcı bulma

    boolean existsByUserNumber(String telephone);

    boolean existsByProfileInfoEmail(String email);

}
