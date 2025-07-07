package akin.city_card.user.repository;

import akin.city_card.user.model.AutoTopUpConfig;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AutoTopUpConfigRepository extends JpaRepository<AutoTopUpConfig,Long> {
    List<AutoTopUpConfig> findByUser(User user);

    List<AutoTopUpConfig> findByUserId(Long id);
}
