package akin.city_card.contract.service.concretes;

import akin.city_card.contract.core.response.ContractStatsDTO;
import akin.city_card.contract.model.Contract;
import akin.city_card.contract.model.ContractType;
import akin.city_card.contract.model.UserContractAcceptance;
import akin.city_card.contract.repository.ContractRepository;
import akin.city_card.contract.repository.UserContractAcceptanceRepository;
import akin.city_card.contract.service.abstacts.ContractAuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class ContractAuditManager implements ContractAuditService {

    private final ContractRepository contractRepository;
    private final UserContractAcceptanceRepository acceptanceRepository;

    @Override
    public ContractStatsDTO getContractStatistics(Long contractId) {
        Contract contract = contractRepository.findById(contractId)
                .orElseThrow(() -> new RuntimeException("Sözleşme bulunamadı"));

        long totalAcceptances = acceptanceRepository.countAcceptancesByContract(contract);
        long totalRejections = acceptanceRepository.countRejectionsByContract(contract);
        long totalActions = totalAcceptances + totalRejections;

        return ContractStatsDTO.builder()
                .contractId(contractId)
                .contractTitle(contract.getTitle())
                .contractVersion(contract.getVersion())
                .contractType(contract.getType())
                .totalAcceptances(totalAcceptances)
                .totalRejections(totalRejections)
                .totalActions(totalActions)
                .acceptanceRate(totalActions > 0 ? (double) totalAcceptances / totalActions * 100 : 0.0)
                .rejectionRate(totalActions > 0 ? (double) totalRejections / totalActions * 100 : 0.0)
                .build();
    }

    @Override
    public Map<ContractType, ContractStatsDTO> getStatsByContractType() {
        Map<ContractType, ContractStatsDTO> typeStats = new HashMap<>();

        for (ContractType type : ContractType.values()) {
            List<Contract> contractsOfType = contractRepository.findByTypeAndActiveOrderByCreatedAtDesc(type, true);

            long totalAcceptances = 0;
            long totalRejections = 0;

            for (Contract contract : contractsOfType) {
                totalAcceptances += acceptanceRepository.countAcceptancesByContract(contract);
                totalRejections += acceptanceRepository.countRejectionsByContract(contract);
            }

            long totalActions = totalAcceptances + totalRejections;

            ContractStatsDTO stats = ContractStatsDTO.builder()
                    .contractType(type)
                    .totalAcceptances(totalAcceptances)
                    .totalRejections(totalRejections)
                    .totalActions(totalActions)
                    .acceptanceRate(totalActions > 0 ? (double) totalAcceptances / totalActions * 100 : 0.0)
                    .rejectionRate(totalActions > 0 ? (double) totalRejections / totalActions * 100 : 0.0)
                    .contractCount(contractsOfType.size())
                    .build();

            typeStats.put(type, stats);
        }

        return typeStats;
    }

    @Override
    public List<UserContractAcceptance> getAcceptancesByDateRange(LocalDateTime startDate, LocalDateTime endDate) {
        return acceptanceRepository.findByAcceptedAtBetween(startDate, endDate);
    }

    @Override
    public Map<String, Object> getOverallStatistics() {
        Map<String, Object> stats = new HashMap<>();

        // Genel sözleşme istatistikleri
        long totalContracts = contractRepository.count();
        long activeContracts = contractRepository.findByActiveOrderByCreatedAtDesc(true).size();
        long mandatoryContracts = contractRepository.findByMandatoryAndActive(true, true).size();

        // Genel kabul/red istatistikleri
        List<UserContractAcceptance> allAcceptances = acceptanceRepository.findAll();
        long totalAcceptances = allAcceptances.stream().mapToLong(a -> a.isAccepted() ? 1 : 0).sum();
        long totalRejections = allAcceptances.size() - totalAcceptances;

        stats.put("totalContracts", totalContracts);
        stats.put("activeContracts", activeContracts);
        stats.put("mandatoryContracts", mandatoryContracts);
        stats.put("totalAcceptances", totalAcceptances);
        stats.put("totalRejections", totalRejections);
        stats.put("totalUserActions", allAcceptances.size());

        if (allAcceptances.size() > 0) {
            stats.put("overallAcceptanceRate", (double) totalAcceptances / allAcceptances.size() * 100);
            stats.put("overallRejectionRate", (double) totalRejections / allAcceptances.size() * 100);
        } else {
            stats.put("overallAcceptanceRate", 0.0);
            stats.put("overallRejectionRate", 0.0);
        }

        return stats;
    }
}



