// ContractAuditService.java
package akin.city_card.contract.service.abstacts;

import akin.city_card.contract.core.response.ContractStatsDTO;
import akin.city_card.contract.model.ContractType;
import akin.city_card.contract.model.UserContractAcceptance;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public interface ContractAuditService {

    ContractStatsDTO getContractStatistics(Long contractId);

    Map<ContractType, ContractStatsDTO> getStatsByContractType();

    List<UserContractAcceptance> getAcceptancesByDateRange(LocalDateTime startDate, LocalDateTime endDate);

    Map<String, Object> getOverallStatistics();
}