package akin.city_card.user.repository;

import akin.city_card.user.model.IdentityVerificationRequest;
import akin.city_card.user.model.RequestStatus;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface IdentityVerificationRequestRepository extends JpaRepository<IdentityVerificationRequest, Long> {
    List<IdentityVerificationRequest> findByRequestedBy(User user);

    Page<IdentityVerificationRequest> findAllByStatusAndRequestedAtBetween(RequestStatus status, LocalDateTime start, LocalDateTime end, Pageable pageable);

    Page<IdentityVerificationRequest> findAllByRequestedAtBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);
}
