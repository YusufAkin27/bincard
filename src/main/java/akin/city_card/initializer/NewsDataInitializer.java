package akin.city_card.initializer;

import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsPriority;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.news.repository.NewsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

@Component
@RequiredArgsConstructor
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
                            "https://images.unsplash.com/photo-1531497865144-0464ef8fbf57",
                            NewsType.GUNCELLEME, NewsPriority.ORTA_YUKSEK
                    ),
                    createNews(
                            "Yeni Metro Hattı Hizmete Girdi!",
                            """
                            İstanbul'da beklenen metro hattı bu sabah hizmete açıldı.
                            Yeni hat, şehir içi ulaşımı önemli ölçüde rahatlatacak ve her gün 500 bin kişiyi taşıyacak kapasitede olacak.
                            Açılışa Ulaştırma Bakanı da katıldı.
                            """,
                            "https://images.unsplash.com/photo-1599232384785-fd5c87d5161d",
                            NewsType.ETKINLIK, NewsPriority.ORTA_YUKSEK
                    ),
                    createNews(
                            "Bilim İnsanları Yeni Gezegen Keşfetti",
                            """
                            NASA, Dünya'ya 300 ışık yılı uzaklıkta yaşama elverişli yeni bir gezegen keşfetti.
                            Gezegenin su barındırma ihtimali oldukça yüksek.
                            Uzay ajansları bu keşfi, 'ikinci Dünya' olarak tanımlıyor.
                            """,
                            "https://images.unsplash.com/photo-1470290378698-263fa7ca0f4c",
                            NewsType.BAKIM, NewsPriority.KRITIK
                    ),
                    createNews(
                            "2025 Yaz Trendleri Açıklandı",
                            """
                            Moda dünyasında 2025 yaz sezonunda pastel tonlar, keten kumaşlar ve doğal dokular öne çıkıyor.
                            Sokak modasında ise rahatlık ve şıklık bir arada sunuluyor.
                            Ünlü markalar yeni koleksiyonlarını tanıttı.
                            """,
                            "https://images.unsplash.com/photo-1516762689617-e1cffcef479d",
                            NewsType.BASIN_BULTENI, NewsPriority.DUSUK
                    ),
                    createNews(
                            "Sağlıklı Beslenmede Yeni Trend: Fermente Gıdalar",
                            """
                            Probiyotik açısından zengin fermente gıdalar, bağışıklık sistemini güçlendirmede etkili oluyor.
                            Yoğurt, kefir ve kombucha gibi ürünlere ilgi her geçen gün artıyor.
                            Uzmanlar, bu gıdaların haftalık diyetlere mutlaka eklenmesini öneriyor.
                            """,
                            "https://images.unsplash.com/photo-1613141412076-88d1cf3ca0c7",
                            NewsType.KESINTI, NewsPriority.NORMAL
                    ),
                    createNews(
                            "Üniversitemiz TÜBİTAK Destekli Projede Yer Alacak",
                            """
                            Üniversitemiz Bilgisayar Mühendisliği bölümü, TÜBİTAK tarafından desteklenen
                            yapay zeka projesinde yer almaya hak kazandı. Proje kapsamında otonom araçların
                            veri işleme teknolojileri geliştirilecek.
                            """,
                            "https://images.unsplash.com/photo-1603357463240-3387a3871f6e",
                            NewsType.BAKIM, NewsPriority.NORMAL
                    ),
                    createNews(
                            "Kampüste Yaz Şenlikleri Başlıyor!",
                            """
                            Her yıl düzenlenen geleneksel yaz şenlikleri bu hafta sonu başlıyor.
                            Konserler, oyunlar, stantlar ve yarışmalarla öğrencileri dolu dolu bir etkinlik bekliyor.
                            Katılım tüm öğrencilere açık ve ücretsizdir.
                            """,
                            "https://images.unsplash.com/photo-1508609349937-5ec4ae374ebf",
                            NewsType.DUYURU, NewsPriority.KRITIK
                    ),
                    createNews(
                            "Doğal Afetlere Karşı Yeni Erken Uyarı Sistemi Geliştirildi",
                            """
                            TÜBİTAK destekli ekip, deprem ve sel gibi afetlerde erken müdahale sağlayacak bir uyarı sistemi geliştirdi.
                            Bu sistem, afet gerçekleşmeden önce 30 saniyelik erken bildirim sağlayabiliyor.
                            """,
                            "https://images.unsplash.com/photo-1581579186989-2c9370e2b4a6",
                            NewsType.BAKIM, NewsPriority.YUKSEK
                    ),
                    createNews(
                            "Öğrencilere Özel Yeni Burs Programı Başladı",
                            """
                            Üniversite yönetimi, ihtiyaç sahibi öğrenciler için 12 ay sürecek yeni bir burs programı başlattı.
                            Başvurular öğrenci işleri sayfasından yapılabilecek.
                            """,
                            "https://images.unsplash.com/photo-1580584126903-c17d7aa2b290",
                            NewsType.BILGILENDIRME, NewsPriority.COK_DUSUK
                    ),
                    createNews(
                            "Geleceğin Meslekleri: Veri Bilimi ve Yapay Zeka",
                            """
                            Dünya Ekonomik Forumu'nun yayınladığı rapora göre, önümüzdeki 10 yılda en çok talep görecek meslekler
                            arasında veri bilimi, yapay zeka mühendisliği ve siber güvenlik uzmanlığı yer alıyor.
                            Gençler bu alanlara yönlendiriliyor.
                            """,
                            "https://images.unsplash.com/photo-1526378722484-bd91ca387e72",
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
