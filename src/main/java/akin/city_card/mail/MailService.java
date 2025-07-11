package akin.city_card.mail;

import akin.city_card.news.model.News;
import akin.city_card.user.exceptions.EmailSendException;

import akin.city_card.user.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@RequiredArgsConstructor
@Slf4j
public class MailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String senderEmail;

    private final EmailQueue emailQueue = new EmailQueue();
    private final ExecutorService executorService = Executors.newFixedThreadPool(5);

    // E-posta kuyruğuna ekleme
    public void queueEmail(EmailMessage emailMessage) {
        emailQueue.enqueue(emailMessage);
        executorService.submit(() -> processEmail(emailMessage));
    }

    // E-postayı işleyip gönderen metot
    private void processEmail(EmailMessage email) {
        sendEmail(email);
    }

    // E-posta gönderme işlemi
    private void sendEmail(EmailMessage email) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();

        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setTo(email.getToEmail());
            helper.setSubject(email.getSubject());
            helper.setText(email.getBody(), email.isHtml());
            helper.setFrom(senderEmail);

            try {
                mailSender.send(mimeMessage);
                log.info("📧 E-posta başarıyla gönderildi: {}", email.getToEmail());
            } catch (Exception e) {
                throw new EmailSendException();
            }

        } catch (MessagingException | EmailSendException e) {
            log.error("E-posta hazırlanırken hata oluştu: {}", e.getMessage());
        }
    }

    // Her 1 dakikada bir kuyruktaki e-postaları gönder
    @Scheduled(fixedRate = 60000)
    public void sendQueuedEmails() {
        int batchSize = Math.max(1, emailQueue.size());
        processBatchEmails(batchSize);
    }

    private void processBatchEmails(int batchSize) {
        List<EmailMessage> emailBatch = new ArrayList<>();

        while (!emailQueue.isEmpty() && emailBatch.size() < batchSize) {
            try {
                emailBatch.add(emailQueue.dequeue());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("E-posta gönderim işlemi kesildi: {}", e.getMessage());
            }
        }

        for (EmailMessage email : emailBatch) {
            executorService.submit(() -> sendEmail(email));
        }
    }
    public void sendNewsNotificationEmail(User user, News news) {
        String toEmail = (user.getProfileInfo() != null) ? user.getProfileInfo().getEmail() : null;
        if (toEmail == null) return;

        String fullName = user.getProfileInfo().getName() + " " + user.getProfileInfo().getSurname();
        String contentSnippet = news.getContent().substring(0, Math.min(200, news.getContent().length())) + "...";

        log.info("📩 Mail gönderimi kuyruğa alındı: {} ({})", fullName, toEmail);

        String htmlBody = String.format("""
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f2f2f2;
                    padding: 20px;
                }
                .container {
                    background-color: #ffffff;
                    max-width: 650px;
                    margin: auto;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }
                .header {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .news-image {
                    width: 100%%;
                    max-height: 300px;
                    object-fit: cover;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }
                .highlight {
                    color: #0a58ca;
                    font-weight: bold;
                }
                .content {
                    color: #333333;
                    font-size: 15px;
                    line-height: 1.6;
                }
                .footer {
                    font-size: 12px;
                    color: #888888;
                    text-align: center;
                    margin-top: 40px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Sayın %s,</h2>
                    <p class="highlight">%s kategorisinde yeni bir haber yayınlandı!</p>
                </div>

                %s <!-- Görsel HTML burada -->

                <div class="content">
                    <p><strong>Başlık:</strong> %s</p>
                    <p><strong>İçerik Özeti:</strong><br>%s</p>
                    <p>Daha fazlası için lütfen uygulamamızı ziyaret ediniz.</p>
                </div>

                <div class="footer">
                    &copy; 2025 Akin City Card • Tüm hakları saklıdır.
                </div>
            </div>
        </body>
        </html>
        """,
                fullName,
                news.getType().name(),
                news.getImage() != null && !news.getImage().isBlank()
                        ? "<img src=\"" + news.getImage() + "\" alt=\"Haber Görseli\" class=\"news-image\" />"
                        : "",
                news.getTitle(),
                contentSnippet
        );

        EmailMessage email = new EmailMessage();
        email.setToEmail(toEmail);
        email.setSubject("Yeni Haber Bildirimi - Akin City Card");
        email.setBody(htmlBody);
        email.setHtml(true);

        queueEmail(email);
    }


}