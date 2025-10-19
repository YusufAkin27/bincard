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
public class ContractDTO {

    private Long id;
    private String title;
    private String content;
    private String version;
    private ContractType type;
    private boolean mandatory;
    private boolean active;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdByUsername;
}