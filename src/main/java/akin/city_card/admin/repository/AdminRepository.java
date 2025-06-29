package akin.city_card.admin.repository;

import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminRepository extends JpaRepository<Admin, Long> {
    Admin findByUserNumber(String username);
    boolean existsByUserNumber(String telephone);

}
