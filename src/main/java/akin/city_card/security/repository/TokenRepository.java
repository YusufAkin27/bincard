package akin.city_card.security.repository;



import akin.city_card.security.entity.Token;
import akin.city_card.security.entity.enums.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {




    Optional<Token> findByTokenValue(String token);

    Optional<Token> findTokenBySecurityUser_IdAndTokenType(Long id, TokenType tokenType);

    void deleteAllBySecurityUser_Id(Long id);
}
