package akin.city_card.mail;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmailMessage {
    private String toEmail;
    private String subject;
    private String body;
    private boolean isHtml;
    private List<EmailAttachment> attachments;


}