// ContractStatsDTO.java
package akin.city_card.contract.core.response;

import akin.city_card.contract.model.ContractType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContractStatsDTO {

    private Long contractId;
    private String contractTitle;
    private String contractVersion;
    private ContractType contractType;

    private long totalAcceptances;
    private long totalRejections;
    private long totalActions;
    private long contractCount; // Tip bazında istatistikler için

    private double acceptanceRate; // Yüzde olarak
    private double rejectionRate; // Yüzde olarak
}