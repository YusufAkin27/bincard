package akin.city_card.report.core.response;

import akin.city_card.report.model.MessageSender;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class MessageDTO {
    private Long id;
    private String message;
    private MessageSender sender;
    private SimpleUserDTO user;
    private SimpleAdminDTO admin;
    private List<AttachmentDTO> attachments;
    private LocalDateTime sentAt;
    private LocalDateTime editedAt;
    private boolean edited;
    private boolean deleted;
    private boolean readByUser;
    private boolean readByAdmin;
}