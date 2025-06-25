package akin.city_card.security.repository;



import akin.city_card.security.entity.Token;
import akin.city_card.security.entity.enums.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {


    // Belirli bir kullanıcıya ait tüm tokenları sil (hem access hem refresh)
    void deleteBySecurityUserId(Long userId);


    Optional<Token> findByTokenValue(String token);

    Optional<Token> findTokenBySecurityUser_IdAndTokenType(Long id, TokenType tokenType);

    List<Token> findAllBySecurityUserId(Long id);
}
