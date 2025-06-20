package akin.city_card.user.repository;

import akin.city_card.user.model.AutoTopUpLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AutoTopUpLogRepository extends JpaRepository<AutoTopUpLog,Long> {
}
