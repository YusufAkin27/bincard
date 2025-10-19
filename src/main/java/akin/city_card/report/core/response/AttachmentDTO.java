package akin.city_card.report.core.response;

import akin.city_card.report.model.AttachmentType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AttachmentDTO {
    private Long id;
    private String fileUrl;
    private AttachmentType type;
    private String fileName;
    private Long fileSize;
}
