// ContractRepository.java
package akin.city_card.contract.repository;

import akin.city_card.contract.model.Contract;
import akin.city_card.contract.model.ContractType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ContractRepository extends JpaRepository<Contract, Long> {

    List<Contract> findAllByOrderByCreatedAtDesc();

    List<Contract> findByActiveOrderByCreatedAtDesc(boolean active);

    List<Contract> findByMandatoryAndActiveOrderByCreatedAtDesc(boolean mandatory, boolean active);

    List<Contract> findByTypeAndActiveOrderByCreatedAtDesc(ContractType type, boolean active);

    List<Contract> findByMandatoryAndActive(boolean mandatory, boolean active);

    boolean existsByTypeAndActive(ContractType type, boolean active);

    Optional<Contract> findByIdAndActive(Long contractId, boolean b);

    Optional<Contract> findTopByTypeAndActiveOrderByCreatedAtDesc(ContractType type, boolean b);
}
