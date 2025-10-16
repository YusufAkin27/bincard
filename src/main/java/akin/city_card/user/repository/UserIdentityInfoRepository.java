package akin.city_card.user.repository;

import akin.city_card.user.model.UserIdentityInfo;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserIdentityInfoRepository extends JpaRepository<UserIdentityInfo, Long> {
}
