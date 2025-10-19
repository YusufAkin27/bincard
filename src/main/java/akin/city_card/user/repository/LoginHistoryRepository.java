package akin.city_card.user.repository;

import akin.city_card.admin.model.Admin;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface LoginHistoryRepository extends JpaRepository<LoginHistory, Long> {
    List<LoginHistory> findAllByUserOrderByLoginAtDesc(Admin admin);

    Page<LoginHistory> findByUserAndLoginAtBetweenOrderByLoginAtDesc(User user, LocalDateTime start, LocalDateTime end, Pageable pageable);

    Page<LoginHistory> findByUserAndLoginAtAfterOrderByLoginAtDesc(User user, LocalDateTime start, Pageable pageable);

    Page<LoginHistory> findByUserAndLoginAtBeforeOrderByLoginAtDesc(User user, LocalDateTime end, Pageable pageable);

    Page<LoginHistory> findByUserOrderByLoginAtDesc(User user, Pageable pageable);
}
