package akin.city_card.buscard.repository;

import akin.city_card.buscard.model.QrToken;
import io.lettuce.core.dynamic.annotation.Param;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;


import java.util.Optional;


public interface QRTokenRepository extends JpaRepository<QrToken,Long> {
    Optional<QrToken> findByToken(String token);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select q from QrToken q where q.token = :token")
    Optional<QrToken> findByTokenForUpdate(@Param("token") String token);
}
