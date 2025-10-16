// ===== CONVERTERS =====

package akin.city_card.contract.core.converter;

import akin.city_card.contract.core.response.AcceptedContractDTO;
import akin.city_card.contract.core.response.ContractDTO;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.model.Contract;
import akin.city_card.contract.model.UserContractAcceptance;
import org.springframework.stereotype.Component;

@Component
public class ContractConverterImpl implements ContractConverter {

    public ContractDTO mapToContractDTO(Contract contract) {
        return ContractDTO.builder()
                .id(contract.getId())
                .title(contract.getTitle())
                .content(contract.getContent())
                .version(contract.getVersion())
                .type(contract.getType())
                .mandatory(contract.isMandatory())
                .active(contract.isActive())
                .createdAt(contract.getCreatedAt())
                .updatedAt(contract.getUpdatedAt())
                .createdByUsername(contract.getCreatedBy() != null ? contract.getCreatedBy().getUsername() : null)
                .build();
    }

    public UserContractDTO mapToUserContractDTO(Contract contract, UserContractAcceptance acceptance) {
        return UserContractDTO.builder()
                .id(contract.getId())
                .title(contract.getTitle())
                .content(contract.getContent())
                .version(contract.getVersion())
                .type(contract.getType())
                .mandatory(contract.isMandatory())
                .active(contract.isActive())
                .createdAt(contract.getCreatedAt())
                .userAccepted(acceptance != null ? acceptance.isAccepted() : null)
                .userActionDate(acceptance != null ? acceptance.getAcceptedAt() : null)
                .rejectionReason(acceptance != null ? acceptance.getRejectionReason() : null)
                .build();
    }

    public AcceptedContractDTO mapToAcceptedContractDTO(UserContractAcceptance acceptance) {
        Contract contract = acceptance.getContract();
        return AcceptedContractDTO.builder()
                .contractId(contract.getId())
                .contractTitle(contract.getTitle())
                .contractVersion(acceptance.getContractVersion())
                .contractType(contract.getType())
                .contractMandatory(contract.isMandatory())
                .acceptanceId(acceptance.getId())
                .accepted(acceptance.isAccepted())
                .acceptedAt(acceptance.getAcceptedAt())
                .ipAddress(acceptance.getIpAddress())
                .userAgent(acceptance.getUserAgent())
                .rejectionReason(acceptance.getRejectionReason())
                .build();
    }

}