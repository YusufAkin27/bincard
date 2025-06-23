package akin.city_card.user.repository;

import akin.city_card.user.model.TwoFactorAuth;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TwoFactorAuthRepository extends JpaRepository<TwoFactorAuth, Integer> {
}
