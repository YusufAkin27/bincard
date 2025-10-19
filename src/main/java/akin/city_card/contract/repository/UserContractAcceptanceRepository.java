package akin.city_card.contract.repository;

import akin.city_card.contract.model.Contract;
import akin.city_card.contract.model.UserContractAcceptance;
import akin.city_card.security.entity.SecurityUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserContractAcceptanceRepository extends JpaRepository<UserContractAcceptance, Long> {

    List<UserContractAcceptance> findByUser(SecurityUser user);

    List<UserContractAcceptance> findByUserAndAcceptedOrderByAcceptedAtDesc(SecurityUser user, boolean accepted);

    List<UserContractAcceptance> findByContract(Contract contract);

    List<UserContractAcceptance> findByContractAndAccepted(Contract contract, boolean accepted);

    boolean existsByUserAndContract(SecurityUser user, Contract contract);

    boolean existsByUserAndContractAndAccepted(SecurityUser user, Contract contract, boolean accepted);

    Optional<UserContractAcceptance> findByUserAndContract(SecurityUser user, Contract contract);

    @Query("SELECT uca FROM UserContractAcceptance uca WHERE uca.user = :user AND uca.contract = :contract ORDER BY uca.acceptedAt DESC")
    Optional<UserContractAcceptance> findLatestByUserAndContract(@Param("user") SecurityUser user, @Param("contract") Contract contract);

    @Query("SELECT COUNT(uca) FROM UserContractAcceptance uca WHERE uca.contract = :contract AND uca.accepted = true")
    long countAcceptancesByContract(@Param("contract") Contract contract);

    @Query("SELECT COUNT(uca) FROM UserContractAcceptance uca WHERE uca.contract = :contract AND uca.accepted = false")
    long countRejectionsByContract(@Param("contract") Contract contract);

    @Query("SELECT uca FROM UserContractAcceptance uca WHERE uca.acceptedAt BETWEEN :startDate AND :endDate")
    List<UserContractAcceptance> findByAcceptedAtBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    @Query("SELECT uca FROM UserContractAcceptance uca WHERE uca.user = :user AND uca.accepted = true AND uca.contract.mandatory = true")
    List<UserContractAcceptance> findAcceptedMandatoryContractsByUser(@Param("user") SecurityUser user);

    void deleteByUserAndContractAndAccepted(SecurityUser user, Contract contract, boolean b);
}