package akin.city_card.user.repository;

import akin.city_card.user.model.IdentityVerificationRequest;
import akin.city_card.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IdentityVerificationRequestRepository extends JpaRepository<IdentityVerificationRequest,Long> {
    List<IdentityVerificationRequest> findByRequestedBy(User user);
}
