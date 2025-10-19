package akin.city_card.superadmin.repository;

import akin.city_card.superadmin.model.SuperAdmin;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SuperAdminRepository extends JpaRepository<SuperAdmin, Long> {
    SuperAdmin findByUserNumber(String phoneNumber);

    boolean existsByUserNumber(String username);
}
