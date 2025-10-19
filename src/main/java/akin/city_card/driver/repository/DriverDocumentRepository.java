package akin.city_card.driver.repository;

import akin.city_card.driver.model.DriverDocument;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface DriverDocumentRepository extends JpaRepository<DriverDocument, Long> {

    // Sürücüye ait belgeler
    Page<DriverDocument> findByDriverIdOrderByIdDesc(Long driverId, Pageable pageable);

    List<DriverDocument> findByDriverIdOrderByIdDesc(Long driverId);

    // Belge tipi bazlı sorgular
    List<DriverDocument> findByDriverIdAndDocumentType(Long driverId, String documentType);

    // Süresi dolacak belgeler
    List<DriverDocument> findByExpiryDateBeforeOrderByExpiryDate(LocalDate expiryDate);

    List<DriverDocument> findByDriverIdAndExpiryDateBefore(Long driverId, LocalDate expiryDate);

    // Belge sayısı
    long countByDriverId(Long driverId);

    long countByDriverIdAndDocumentType(Long driverId, String documentType);
}