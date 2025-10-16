package akin.city_card.initializer;

import akin.city_card.feedback.model.Feedback;
import akin.city_card.feedback.model.FeedbackType;
import akin.city_card.feedback.repository.FeedbackRepository;
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
@Order(13)
public class FeedbackDataInitializer implements ApplicationRunner {

    private final FeedbackRepository feedbackRepository;
    private final UserRepository userRepository;

    private final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        if (feedbackRepository.count() == 0) {
            createSampleFeedbacks();
            System.out.println(">> 10 adet örnek feedback oluşturuldu.");
        }
    }

    private void createSampleFeedbacks() {
        List<User> users = userRepository.findAll();

        if (users.isEmpty()) {
            System.out.println("⚠️ Kullanıcı verisi bulunamadı. Feedback initializer çalıştırılamadı.");
            return;
        }

        List<Feedback> feedbacks = new ArrayList<>();

        // 1. Mobil Uygulama Önerisi
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.SUGGESTION,
                "Mobil Uygulama Geliştirme Önerisi",
                "Mobil uygulamaya kart bakiyesi bittiğinde otomatik yükleme özelliği eklenebilir. Apple Pay ve Google Pay entegrasyonu da olursa çok güzel olur. Ayrıca geçmiş yolculuk geçmişini haritada gösterebilsek süper olur.",
                "mobile",
                null,
                2
        ));

        // 2. Durak Temizliği Şikayeti
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.COMPLAINT,
                "Durak Temizlik Sorunu",
                "Kadıköy metro durağında sürekli kötü koku var. Tuvaletler çok kirli ve sabun hiç bitmiyor. Temizlik ekipleri daha sık gelirse iyi olur. Özellikle akşam saatlerinde durum çok kötü oluyor.",
                "web",
                "https://example.com/kadikoy-durak-photo.jpg",
                5
        ));

        // 3. Kart Okuyucu Teknik Hata
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.TECHNICAL_ISSUE,
                "Turnike Kart Okuyucu Sorunu",
                "Beşiktaş İskelesi'ndeki turnikelerden 3 tanesi düzgün kart okuymuyor. Kartı 4-5 defa deniyorum, bazen hiç açılmıyor. Teknik ekip kontrol edebilir mi? Sabah saatlerinde çok kuyruk oluyor bu yüzden.",
                "mobile",
                null,
                1
        ));

        // 4. Sıcaklık Kontrolü Önerisi
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.SUGGESTION,
                "Araçlarda Klima Ayarı",
                "Yaz aylarında otobüslerde klima çok soğuk, kış aylarında çok sıcak oluyor. Şoförlerin klimayı ayarlarken dış hava durumunu dikkate almasını sağlayacak bir sistem kurulabilir mi?",
                "web",
                null,
                4
        ));

        // 5. Müşteri Hizmetleri Şikayeti
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.COMPLAINT,
                "Çağrı Merkezi Bekleme Süresi",
                "444 4 İBB'yi arayarak kart sorunum için bilgi almak istedim ama 25 dakika bekledim ve kimse açmadı. Bu kadar uzun bekleme süresi kabul edilemez. Daha fazla operatör alınmalı.",
                "mobile",
                null,
                7
        ));

        // 6. Uygulama Çökme Hatası
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.TECHNICAL_ISSUE,
                "Mobil Uygulama Çöküyor",
                "İPhone 14'te İstanbulkart uygulaması sürekli çöküyor. Bakiye sorgularken veya QR kod okutmaya çalışırken donuyor. Son güncellemeden sonra başladı bu sorun. iOS 17.1 kullanıyorum.",
                "mobile",
                null,
                0
        ));

        // 7. Engelli Erişimi Önerisi
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.SUGGESTION,
                "Engelli Vatandaşlar İçin İyileştirme",
                "Metro duralarında sesli anons sistemi çok güzel ama görme engelli vatandaşlar için turnike geçiş seslerini daha belirgin yapabilir misiniz? Ayrıca braille alfabesiyle kart yükleme noktalarında bilgilendirme olsa güzel olur.",
                "terminal",
                null,
                3
        ));

        // 8. Personel Davranışı Şikayeti
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.COMPLAINT,
                "Gişe Personeli Kaba Davranış",
                "Eminönü metrobüs durağındaki gişe personeli çok kaba konuştu. Kart problemimi anlatmaya çalışırken sürekli sözümü kesti ve sinirli bir şekilde cevap verdi. Bu tavır hiç hoş değil.",
                "terminal",
                null,
                6
        ));

        // 9. Barkod Okuma Hatası
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.TECHNICAL_ISSUE,
                "QR Kod Okuyucu Problemi",
                "Uygulamadaki QR kod okuyucu çok yavaş çalışıyor. Kamerayı açtıktan sonra odaklanması 10-15 saniye sürüyor. Bu süre zarfında otobüs geliyor ve kaçırıyorum. Lütfen daha hızlı hale getirebilir misiniz?",
                "mobile",
                null,
                1
        ));

        // 10. Genel Memnuniyet ve Öneri
        feedbacks.add(createFeedback(
                users.get(random.nextInt(users.size())),
                FeedbackType.OTHER,
                "Genel Değerlendirme ve Teşekkür",
                "İstanbulkart sistemi genel olarak çok başarılı. 15 yıldır kullanıyorum ve büyük gelişim gösterdi. Tek önerim, kart yükleme noktalarının sayısının artırılması. Özellikle Anadolu yakasında az. Emeği geçen herkese teşekkürler.",
                "web",
                null,
                8
        ));

        feedbackRepository.saveAll(feedbacks);
    }

    private Feedback createFeedback(User user, FeedbackType type, String subject,
                                    String message, String source, String photoUrl, int daysAgo) {
        return Feedback.builder()
                .user(user)
                .type(type)
                .subject(subject)
                .message(message)
                .source(source)
                .photoUrl(photoUrl)
                .submittedAt(LocalDateTime.now().minusDays(daysAgo).minusHours(random.nextInt(24)))
                .updatedAt(LocalDateTime.now().minusDays(daysAgo).minusHours(random.nextInt(24)))
                .build();
    }
}