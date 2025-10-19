package akin.city_card.security.repository;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.entity.Token;
import akin.city_card.security.entity.enums.TokenType;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    @Modifying
    @Transactional
    @Query("DELETE FROM Token t WHERE t.securityUser = :user")
    void deleteAllTokensByUser(@Param("user") SecurityUser user);

    @Modifying
    @Transactional
    @Query("DELETE FROM Token t WHERE t.securityUser = :user AND t.tokenType = :tokenType")
    void deleteBySecurityUserAndTokenType(@Param("user") SecurityUser user, @Param("tokenType") TokenType tokenType);

    @Modifying
    @Transactional
    @Query("DELETE FROM Token t WHERE t.securityUser.id = :userId AND t.tokenType = :tokenType")
    void deleteByUserIdAndTokenType(@Param("userId") Long userId, @Param("tokenType") TokenType tokenType);

    Optional<Token> findByTokenValue(String token);

    List<Token> findAllBySecurityUserId(Long id);

    @Query("SELECT t FROM Token t WHERE t.securityUser = :user AND t.tokenType = :tokenType AND t.isValid = true")
    List<Token> findActiveTokensByUserAndType(@Param("user") SecurityUser user, @Param("tokenType") TokenType tokenType);

    @Query("SELECT COUNT(t) FROM Token t WHERE t.securityUser = :user AND t.tokenType = :tokenType AND t.isValid = true")
    long countActiveTokensByUserAndType(@Param("user") SecurityUser user, @Param("tokenType") TokenType tokenType);

    @Modifying
    @Transactional
    @Query("UPDATE Token t SET t.isValid = false, t.revokedAt = CURRENT_TIMESTAMP, t.revokeReason = :reason WHERE t.securityUser = :user")
    void revokeAllUserTokens(@Param("user") SecurityUser user, @Param("reason") String reason);
}