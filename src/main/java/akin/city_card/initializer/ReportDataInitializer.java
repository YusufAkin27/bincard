package akin.city_card.initializer;

import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.report.model.*;
import akin.city_card.report.repository.ReportMessageRepository;
import akin.city_card.report.repository.ReportRepository;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Component
@RequiredArgsConstructor
@Order(14)
public class ReportDataInitializer implements ApplicationRunner {

    private final ReportRepository reportRepository;
    private final ReportMessageRepository reportMessageRepository;
    private final UserRepository userRepository;
    private final AdminRepository adminRepository;

    private final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        if (reportRepository.count() == 0) {
            createSampleReports();
            System.out.println(">> 10 adet örnek rapor ve mesajlar oluşturuldu.");
        }
    }

    private void createSampleReports() {
        List<User> users = userRepository.findAll().stream().limit(10).toList();
        List<Admin> admins = adminRepository.findAll().stream().limit(3).toList();

        if (users.isEmpty() || admins.isEmpty()) {
            System.out.println("⚠️ Kullanıcı veya admin verisi bulunamadı. Report initializer çalıştırılamadı.");
            return;
        }

        List<Report> reports = new ArrayList<>();

        // 1. Kayıp Eşya Raporu
        Report report1 = createReport(users.get(0), ReportCategory.LOST_ITEM,
                "Bugün otobüste cüzdanımı unuttuğum, içinde kartlarım ve 500 TL param vardı. 15:30 civarında 45A hattında seyahat ediyordum.");
        reports.add(report1);

        // 2. Şoför Şikayeti
        Report report2 = createReport(users.get(1), ReportCategory.DRIVER_COMPLAINT,
                "Bu sabah 34T hattında şoför çok kaba davrandı, yaşlı bir yolcuya bağırdı ve kapıları erken kapatıp beni düşürmedi.");
        reports.add(report2);

        // 3. Kart Sorunu
        Report report3 = createReport(users.get(2), ReportCategory.CARD_ISSUE,
                "Kartımdan para kesildiği halde turnike açılmıyor. Dün akşamdan beri bu sorun devam ediyor, lütfen acil çözüm.");
        reports.add(report3);

        // 4. Servis Gecikmesi
        Report report4 = createReport(users.get(3), ReportCategory.SERVICE_DELAY,
                "Metro hattında sürekli gecikme yaşanıyor. Sabah 08:00'da beklediğim tren 08:25'te geldi, işe geç kaldım.");
        reports.add(report4);

        // 5. Diğer - Temizlik Sorunu
        Report report5 = createReport(users.get(4), ReportCategory.OTHER,
                "Mecidiyeköy metro durağında çok kötü koku var ve temizlik yetersiz. Bu durum sağlık açısından tehlikeli.");
        reports.add(report5);

        // 6. Kayıp Telefon
        Report report6 = createReport(users.get(5), ReportCategory.LOST_ITEM,
                "iPhone 14 Pro modelimi metrobüste unuttum. Siyah renkli, üzerinde mavi kılıf var. Çok önemli verilerim var.");
        reports.add(report6);

        // 7. Şoför Övgüsü (pozitif feedback)
        Report report7 = createReport(users.get(6), ReportCategory.DRIVER_COMPLAINT,
                "17B hattındaki şoför bey çok yardımseverdi, tekerlekli sandalyeli vatandaşa çok güzel yardım etti. Teşekkür ederim.");
        reports.add(report7);

        // 8. Kart Blokajı Sorunu
        Report report8 = createReport(users.get(7), ReportCategory.CARD_ISSUE,
                "Kartım sebepsiz yere bloke olmuş. Hiçbir borucum yok, düzenli kullanıyorum. Neden böyle oldu anlamadım.");
        reports.add(report8);

        // 9. Otobüs Gecikmesi
        Report report9 = createReport(users.get(8), ReportCategory.SERVICE_DELAY,
                "500T hattı son 1 haftadır çok düzensiz çalışıyor. Bazen 40 dakika bekliyorum, çok mağdurum.");
        reports.add(report9);

        // 10. Durak Sorunu
        Report report10 = createReport(users.get(9), ReportCategory.OTHER,
                "Levent metro durağında asansör bozuk, 1 aydır tamir edilmiyor. Yaşlı ve engelli vatandaşlar çok zorlanıyor.");
        reports.add(report10);

        // Raporları kaydet
        reportRepository.saveAll(reports);

        // Her rapora mesajlar ekle
        addMessagesToReport(report1, users.get(0), admins.get(0), "lost_wallet");
        addMessagesToReport(report2, users.get(1), admins.get(1), "driver_complaint");
        addMessagesToReport(report3, users.get(2), admins.get(0), "card_issue");
        addMessagesToReport(report4, users.get(3), admins.get(2), "service_delay");
        addMessagesToReport(report5, users.get(4), admins.get(1), "cleaning");
        addMessagesToReport(report6, users.get(5), admins.get(0), "lost_phone");
        addMessagesToReport(report7, users.get(6), admins.get(2), "positive_feedback");
        addMessagesToReport(report8, users.get(7), admins.get(1), "card_blocked");
        addMessagesToReport(report9, users.get(8), admins.get(0), "bus_delay");
        addMessagesToReport(report10, users.get(9), admins.get(2), "elevator_broken");
    }

    private Report createReport(User user, ReportCategory category, String initialMessage) {
        LocalDateTime createdTime = LocalDateTime.now().minusDays(random.nextInt(7)).minusHours(random.nextInt(24));

        Report report = Report.builder()
                .user(user)
                .category(category)
                .initialMessage(initialMessage)
                .status(getRandomStatus())
                .createdAt(createdTime)
                .lastMessageAt(createdTime)
                .lastMessageSender(MessageSender.USER)
                .unreadByUser(0)
                .unreadByAdmin(random.nextInt(3))
                .deleted(false)
                .isActive(true)
                .archived(false)
                .isRated(false)
                .build();

        return report;
    }

    private void addMessagesToReport(Report report, User user, Admin admin, String conversationType) {
        List<ReportMessage> messages = new ArrayList<>();
        LocalDateTime messageTime = report.getCreatedAt().plusMinutes(10);

        switch (conversationType) {
            case "lost_wallet":
                // Admin yanıtı
                messages.add(createMessage(report, "Merhaba, kaybettiğiniz cüzdan için üzgünüz. Hangi duraktan hangi durağa seyahat ettiniz? Araç plakası hatırlıyor musunuz?",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(15);
                // Kullanıcı yanıtı
                messages.add(createMessage(report, "Kabataş'tan Beşiktaş'a gidiyordum. Plaka tam hatırlamıyorum ama saat 15:30 civarındaydı.",
                        MessageSender.USER, user, null, messageTime));

                messageTime = messageTime.plusHours(2);
                // Admin çözüm
                messages.add(createMessage(report, "Araç şoförü ile iletişime geçtik. Cüzdanınız bulundu! Beşiktaş İskelesi'ndeki büromuzdan teslim alabilirsiniz. Kimlik belgesi getirmeyi unutmayın.",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(5);
                messages.add(createMessage(report, "Çok teşekkür ederim! Yarın sabah gelip alacağım.",
                        MessageSender.USER, user, null, messageTime));

                report.setStatus(ReportStatus.RESOLVED);
                break;

            case "driver_complaint":
                messages.add(createMessage(report, "Şikayetiniz için teşekkürler. Hangi saatte ve hangi durakta yaşandı bu olay? Şoförün fiziksel özelliklerini hatırlıyor musunuz?",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(20);
                messages.add(createMessage(report, "Sabah 8:45'te Mecidiyeköy durağından bindim. Orta yaşlı, kısa boylu, gözlüklü bir şoförtü. Yaşlı amcaya çok kaba davrandı.",
                        MessageSender.USER, user, null, messageTime));

                messageTime = messageTime.plusHours(1);
                messages.add(createMessage(report, "Tarif ettiğiniz şoförü tespit ettik. Kendisi ile görüştük ve uyarıda bulunduk. Bu tür davranışları kesinlikle kabul etmiyoruz.",
                        MessageSender.ADMIN, null, admin, messageTime));

                report.setStatus(ReportStatus.RESOLVED);
                break;

            case "card_issue":
                messages.add(createMessage(report, "Kartınızdaki teknik sorunu çözebiliriz. Kart numaranızın son 4 hanesini paylaşabilir misiniz? Ne zaman son kullandınız?",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(10);
                messages.add(createMessage(report, "Son 4 hane 7542. Dün akşam 19:30'da Taksim'de kullanmaya çalıştım, para kesildi ama geçemedim.",
                        MessageSender.USER, user, null, messageTime));

                messageTime = messageTime.plusMinutes(30);
                messages.add(createMessage(report, "Kartınızı sistemde kontrol ettik ve sorunu tespit ettik. Teknik bir hata vardı, şimdi düzelttik. Kartınızı tekrar deneyebilirsiniz.",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(45);
                messages.add(createMessage(report, "Denedim, şimdi çalışıyor! Çok teşekkürler.",
                        MessageSender.USER, user, null, messageTime));

                report.setStatus(ReportStatus.RESOLVED);
                break;

            case "service_delay":
                messages.add(createMessage(report, "Metro gecikmesi konusundaki şikayetinizi aldık. Bu sabah teknik bir arıza nedeniyle gecikmeler yaşandı. Özür dileriz.",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(25);
                messages.add(createMessage(report, "Anladım ama bu durum çok sık yaşanıyor. Alternatif ulaşım seçeneği sunuluyor mu bu durumda?",
                        MessageSender.USER, user, null, messageTime));

                messageTime = messageTime.plusHours(1);
                messages.add(createMessage(report, "Haklısınız. Bundan sonra böyle durumlarda otobüs seferlerini artıracağız ve mobil uygulamamızdan anlık duyuru yapacağız.",
                        MessageSender.ADMIN, null, admin, messageTime));

                report.setStatus(ReportStatus.IN_REVIEW);
                break;

            case "positive_feedback":
                messages.add(createMessage(report, "Güzel geri bildiriminiz için çok teşekkür ederiz! Bu tür pozitif örnekleri duymak bizi çok mutlu ediyor.",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(15);
                messages.add(createMessage(report, "Gerçekten çok etkilendim, şoför beyin ismi Mehmet'ti galiba. Böyle çalışanlarınız olduğu için gururlu olmalısınız.",
                        MessageSender.USER, user, null, messageTime));

                messageTime = messageTime.plusMinutes(30);
                messages.add(createMessage(report, "Mehmet Bey'e bu güzel sözlerinizi ilettik, çok memnun oldu. Teşekkürleriniz için tekrar sağolun!",
                        MessageSender.ADMIN, null, admin, messageTime));

                report.setStatus(ReportStatus.RESOLVED);
                break;

            default:
                // Basit bir sohbet
                messages.add(createMessage(report, "Sorununuz için teşekkürler, konuyu inceliyoruz.",
                        MessageSender.ADMIN, null, admin, messageTime));

                messageTime = messageTime.plusMinutes(30);
                messages.add(createMessage(report, "Ne zaman bir sonuç alabilir miyim?",
                        MessageSender.USER, user, null, messageTime));

                messageTime = messageTime.plusHours(2);
                messages.add(createMessage(report, "En geç yarın akşama kadar size geri dönüş yapacağız.",
                        MessageSender.ADMIN, null, admin, messageTime));

                report.setStatus(ReportStatus.IN_REVIEW);
                break;
        }

        reportMessageRepository.saveAll(messages);

        // Son mesaj bilgisini güncelle
        if (!messages.isEmpty()) {
            ReportMessage lastMessage = messages.get(messages.size() - 1);
            report.setLastMessageAt(lastMessage.getSentAt());
            report.setLastMessageSender(lastMessage.getSender());
        }

        // Bazı raporlara memnuniyet puanı ekle
        if (report.getStatus() == ReportStatus.RESOLVED && random.nextBoolean()) {
            int rating = 3 + random.nextInt(3); // 3-5 arası puan
            String[] comments = {
                    "Hızlı çözüm için teşekkürler",
                    "Çok memnun kaldım, işlem başarılıydı",
                    "Güler yüzlü hizmet",
                    "Sorun tamamen çözüldü",
                    "Profesyonel yaklaşım"
            };
            report.setSatisfactionRating(rating, comments[random.nextInt(comments.length)]);
        }
    }

    private ReportMessage createMessage(Report report, String message, MessageSender sender,
                                        User user, Admin admin, LocalDateTime sentAt) {
        return ReportMessage.builder()
                .report(report)
                .message(message)
                .sender(sender)
                .user(user)
                .admin(admin != null ? admin : null)
                .sentAt(sentAt)
                .deleted(false)
                .edited(false)
                .readByAdmin(sender == MessageSender.ADMIN)
                .readByUser(sender == MessageSender.USER)
                .build();
    }

    private ReportStatus getRandomStatus() {
        ReportStatus[] statuses = {
                ReportStatus.OPEN,
                ReportStatus.IN_REVIEW,
                ReportStatus.RESOLVED,
                ReportStatus.RESOLVED,  // Daha fazla çözülmüş rapor
                ReportStatus.IN_REVIEW
        };
        return statuses[random.nextInt(statuses.length)];
    }
}