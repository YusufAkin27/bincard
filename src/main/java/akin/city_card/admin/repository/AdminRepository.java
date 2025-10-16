package akin.city_card.admin.repository;

import akin.city_card.admin.model.Admin;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminRepository extends JpaRepository<Admin, Long> {
    boolean existsByUserNumber(String telephone);

    Admin findByUserNumber(String userNumber);
}
