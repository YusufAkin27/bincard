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
public class UserContractDTO {

    private Long id;
    private String title;
    private String content;
    private String version;
    private ContractType type;
    private boolean mandatory;
    private boolean active;
    private LocalDateTime createdAt;

    // Kullanıcının bu sözleşme ile ilgili durumu
    private Boolean userAccepted; // null = henüz işlem yapmamış, true = onaylamış, false = reddetmiş
    private LocalDateTime userActionDate; // Onaylama/reddetme tarihi
    private String rejectionReason; // Reddetme sebebi (varsa)
}