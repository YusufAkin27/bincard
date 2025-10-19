package akin.city_card.contract.core.response;

import akin.city_card.contract.model.ContractType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AcceptedContractDTO {

    private Long contractId;
    private String contractTitle;
    private String contractVersion;
    private ContractType contractType;
    private boolean contractMandatory;

    private Long acceptanceId;
    private boolean accepted;
    private LocalDateTime acceptedAt;
    private String ipAddress;
    private String userAgent;
    private String rejectionReason;
}