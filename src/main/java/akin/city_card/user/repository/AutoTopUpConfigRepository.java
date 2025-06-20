package akin.city_card.user.repository;

import akin.city_card.user.model.AutoTopUpConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AutoTopUpConfigRepository extends JpaRepository<AutoTopUpConfig,Long> {
}
