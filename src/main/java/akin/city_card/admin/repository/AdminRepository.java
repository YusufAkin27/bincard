package akin.city_card.admin.repository;

import akin.city_card.admin.model.Admin;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminRepository extends JpaRepository<Admin, Long> {
    boolean existsByUserNumber(String telephone);

    Admin findByUserNumber(String userNumber);

    Page<Admin> findByStatusAndRole(String status, String role, Pageable pageable);

    Page<Admin> findByProfileInfo_NameContainingIgnoreCaseOrProfileInfo_EmailContainingIgnoreCaseOrUserNumberContainingIgnoreCase(
            String name, String email, String telephone, Pageable pageable);

    Page<Admin> findByStatus(String status, Pageable pageable);

    Page<Admin> findByRole(String role, Pageable pageable);
}
