package akin.city_card.initializer;

import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.news.repository.NewsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

@Component
@RequiredArgsConstructor
@Order(12)
public class NewsDataInitializer implements ApplicationRunner {

    private final NewsRepository newsRepository;

    @Override
    public void run(ApplicationArguments args) {
        if (newsRepository.count() == 0) {
            List<News> newsList = List.of(
                    createNews(
                            "Yapay Zeka ile Eğitimde Devrim!",
                            """
                                    Dünyaca ünlü üniversiteler, yapay zekayı ders içeriklerine entegre etmeye başladı.
                                    Bu teknoloji sayesinde öğrenciler artık kişisel öğrenme deneyimi yaşayabiliyor.
                                    Eğitimdeki bu devrim, özellikle uzaktan eğitimde verimliliği %70'e kadar artırdı.
                                    """,
                            "https://images.pexels.com/photos/32682886/pexels-photo-32682886.jpeg?_gl=1*11hf5b*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTUzMjAkajUkbDAkaDA.",
                            NewsType.GUNCELLEME, NewsPriority.ORTA_YUKSEK
                    ),
                    createNews(
                            "Yeni Metro Hattı Hizmete Girdi!",
                            """
                                    İstanbul'da beklenen metro hattı bu sabah hizmete açıldı.
                                    Yeni hat, şehir içi ulaşımı önemli ölçüde rahatlatacak ve her gün 500 bin kişiyi taşıyacak kapasitede olacak.
                                    Açılışa Ulaştırma Bakanı da katıldı.
                                    """,
                            "https://images.pexels.com/photos/29024422/pexels-photo-29024422.jpeg?_gl=1*1d2woxi*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTUzNDckajU4JGwwJGgw",
                            NewsType.ETKINLIK, NewsPriority.ORTA_YUKSEK
                    ),
                    createNews(
                            "Bilim İnsanları Yeni Gezegen Keşfetti",
                            """
                                    NASA, Dünya'ya 300 ışık yılı uzaklıkta yaşama elverişli yeni bir gezegen keşfetti.
                                    Gezegenin su barındırma ihtimali oldukça yüksek.
                                    Uzay ajansları bu keşfi, 'ikinci Dünya' olarak tanımlıyor.
                                    """,
                            "https://images.pexels.com/photos/31036772/pexels-photo-31036772.jpeg?_gl=1*1nqqbus*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTUzNzQkajMxJGwwJGgw",
                            NewsType.BAKIM, NewsPriority.KRITIK
                    ),
                    createNews(
                            "2025 Yaz Trendleri Açıklandı",
                            """
                                    Moda dünyasında 2025 yaz sezonunda pastel tonlar, keten kumaşlar ve doğal dokular öne çıkıyor.
                                    Sokak modasında ise rahatlık ve şıklık bir arada sunuluyor.
                                    Ünlü markalar yeni koleksiyonlarını tanıttı.
                                    """,
                            "https://images.pexels.com/photos/33314024/pexels-photo-33314024.jpeg?_gl=1*1mqc0cn*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTUxODAkajM4JGwwJGgw",
                            NewsType.BASIN_BULTENI, NewsPriority.DUSUK
                    ),
                    createNews(
                            "Sağlıklı Beslenmede Yeni Trend: Fermente Gıdalar",
                            """
                                    Probiyotik açısından zengin fermente gıdalar, bağışıklık sistemini güçlendirmede etkili oluyor.
                                    Yoğurt, kefir ve kombucha gibi ürünlere ilgi her geçen gün artıyor.
                                    Uzmanlar, bu gıdaların haftalık diyetlere mutlaka eklenmesini öneriyor.
                                    """,
                            "https://videos.pexels.com/video-files/33045211/14084440_1440_2040_25fps.mp4",
                            NewsType.KESINTI, NewsPriority.NORMAL
                    ),
                    createNews(
                            "Üniversitemiz TÜBİTAK Destekli Projede Yer Alacak",
                            """
                                    Üniversitemiz Bilgisayar Mühendisliği bölümü, TÜBİTAK tarafından desteklenen
                                    yapay zeka projesinde yer almaya hak kazandı. Proje kapsamında otonom araçların
                                    veri işleme teknolojileri geliştirilecek.
                                    """,
                            "https://images.pexels.com/photos/32125166/pexels-photo-32125166.jpeg?_gl=1*5goalr*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTUyNzAkajU1JGwwJGgw",
                            NewsType.BAKIM, NewsPriority.NORMAL
                    ),
                    createNews(
                            "Kampüste Yaz Şenlikleri Başlıyor!",
                            """
                                    Her yıl düzenlenen geleneksel yaz şenlikleri bu hafta sonu başlıyor.
                                    Konserler, oyunlar, stantlar ve yarışmalarla öğrencileri dolu dolu bir etkinlik bekliyor.
                                    Katılım tüm öğrencilere açık ve ücretsizdir.
                                    """,
                            "https://videos.pexels.com/video-files/14993440/14993440-uhd_1440_2162_60fps.mp4",
                            NewsType.DUYURU, NewsPriority.KRITIK
                    ),
                    createNews(
                            "Doğal Afetlere Karşı Yeni Erken Uyarı Sistemi Geliştirildi",
                            """
                                    TÜBİTAK destekli ekip, deprem ve sel gibi afetlerde erken müdahale sağlayacak bir uyarı sistemi geliştirdi.
                                    Bu sistem, afet gerçekleşmeden önce 30 saniyelik erken bildirim sağlayabiliyor.
                                    """,
                            "https://images.pexels.com/photos/17131046/pexels-photo-17131046.jpeg?_gl=1*j96usl*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTU0NjUkajkkbDAkaDA.",
                            NewsType.BAKIM, NewsPriority.YUKSEK
                    ),
                    createNews(
                            "Öğrencilere Özel Yeni Burs Programı Başladı",
                            """
                                    Üniversite yönetimi, ihtiyaç sahibi öğrenciler için 12 ay sürecek yeni bir burs programı başlattı.
                                    Başvurular öğrenci işleri sayfasından yapılabilecek.
                                    """,
                            "https://images.pexels.com/photos/33217919/pexels-photo-33217919.jpeg?_gl=1*1xsmqkg*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTU0ODEkajU4JGwwJGgw",
                            NewsType.BILGILENDIRME, NewsPriority.COK_DUSUK
                    ),
                    createNews(
                            "Geleceğin Meslekleri: Veri Bilimi ve Yapay Zeka",
                            """
                                    Dünya Ekonomik Forumu'nun yayınladığı rapora göre, önümüzdeki 10 yılda en çok talep görecek meslekler
                                    arasında veri bilimi, yapay zeka mühendisliği ve siber güvenlik uzmanlığı yer alıyor.
                                    Gençler bu alanlara yönlendiriliyor.
                                    """,
                            "https://images.pexels.com/photos/33202250/pexels-photo-33202250.jpeg?_gl=1*1hl96xw*_ga*MTY4OTU4ODQyNC4xNzU0NDY5NDM4*_ga_8JE65Q40S6*czE3NTQ1NTUxNTgkbzIkZzEkdDE3NTQ1NTU1MDAkajM5JGwwJGgw",
                            NewsType.BASIN_BULTENI, NewsPriority.YUKSEK
                    )
            );

            newsRepository.saveAll(newsList);
            System.out.println(">> 10 gerçekçi haber başarıyla yüklendi.");
        }
    }

    private News createNews(String title, String content, String imageUrl, NewsType type, NewsPriority priority) {
        return News.builder()
                .title(title)
                .content(content)
                .image(imageUrl)
                .startDate(LocalDateTime.now().minusDays(new Random().nextInt(5)))
                .endDate(LocalDateTime.now().plusDays(new Random().nextInt(10) + 3))
                .active(true)
                .platform(PlatformType.ALL)
                .priority(priority)
                .type(type)
                .viewCount(new Random().nextInt(1000))
                .allowFeedback(true)
                .build();
    }
}
