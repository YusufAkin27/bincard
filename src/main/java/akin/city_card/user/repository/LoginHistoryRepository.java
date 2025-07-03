package akin.city_card.user.repository;

import akin.city_card.admin.model.Admin;
import akin.city_card.user.model.LoginHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LoginHistoryRepository extends JpaRepository<LoginHistory,Long> {
    List<LoginHistory> findAllByUserOrderByLoginAtDesc(Admin admin);
}
