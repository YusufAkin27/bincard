package akin.city_card.initializer;

import akin.city_card.paymentPoint.model.Address;
import akin.city_card.paymentPoint.model.Location;
import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.paymentPoint.model.PaymentPoint;
import akin.city_card.paymentPoint.repository.PaymentPointRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.Arrays;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class PaymentPointDataInitializer {

    private final PaymentPointRepository paymentPointRepository;

    @Bean
    @Profile({"dev", "test"}) // Sadece geliştirme ve test ortamlarında çalışacak
    public CommandLineRunner initPaymentPoints() {
        return args -> {
            // Veritabanında veri varsa, tekrar ekleme
            if (paymentPointRepository.count() > 0) {
                return;
            }

            List<PaymentPoint> paymentPoints = Arrays.asList(
                    // 1. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Merkez Belediye Ödeme Noktası")
                            .description("Belediye binasında bulunan ana ödeme noktası")
                            .address(Address.builder()
                                    .street("Cumhuriyet Meydanı No:1")
                                    .district("Merkez")
                                    .city("İstanbul")
                                    .postalCode("34000")
                                    .build())
                            .location(Location.builder()
                                    .latitude(41.0082)
                                    .longitude(28.9784)
                                    .build())
                            .contactNumber("0212 555 1234")
                            .workingHours("09:00-17:00 (Hafta içi)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.CREDIT_CARD, PaymentMethod.DEBIT_CARD))
                            .active(true)
                            .build(),

                    // 2. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Kadıköy Ödeme Merkezi")
                            .description("Kadıköy'deki ana ödeme noktası")
                            .address(Address.builder()
                                    .street("Bahariye Caddesi No:45")
                                    .district("Kadıköy")
                                    .city("İstanbul")
                                    .postalCode("34710")
                                    .build())
                            .location(Location.builder()
                                    .latitude(40.9909)
                                    .longitude(29.0233)
                                    .build())
                            .contactNumber("0216 555 6789")
                            .workingHours("09:00-18:00 (Haftanın her günü)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.CREDIT_CARD))
                            .active(true)
                            .build(),

                    // 3. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Üsküdar Metro İstasyonu")
                            .description("Üsküdar metro istasyonundaki ödeme noktası")
                            .address(Address.builder()
                                    .street("Üsküdar Metro İstasyonu")
                                    .district("Üsküdar")
                                    .city("İstanbul")
                                    .postalCode("34672")
                                    .build())
                            .location(Location.builder()
                                    .latitude(41.0262)
                                    .longitude(29.0150)
                                    .build())
                            .contactNumber("0216 555 4321")
                            .workingHours("06:00-23:00 (Haftanın her günü)")
                            .paymentMethods(Arrays.asList(PaymentMethod.DEBIT_CARD, PaymentMethod.CREDIT_CARD))
                            .active(true)
                            .build(),

                    // 4. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Bebek Sahil Ödeme Noktası")
                            .description("Bebek sahilindeki kart yükleme ve ödeme noktası")
                            .address(Address.builder()
                                    .street("Bebek Sahili")
                                    .district("Beşiktaş")
                                    .city("İstanbul")
                                    .postalCode("34342")
                                    .build())
                            .location(Location.builder()
                                    .latitude(41.0800)
                                    .longitude(29.0434)
                                    .build())
                            .contactNumber("0212 555 8765")
                            .workingHours("10:00-20:00 (Hafta içi), 10:00-22:00 (Hafta sonu)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.CASH))
                            .active(true)
                            .build(),

                    // 5. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Bakırköy Meydanı")
                            .description("Bakırköy meydanındaki ödeme noktası")
                            .address(Address.builder()
                                    .street("Bakırköy Meydanı")
                                    .district("Bakırköy")
                                    .city("İstanbul")
                                    .postalCode("34140")
                                    .build())
                            .location(Location.builder()
                                    .latitude(40.9792)
                                    .longitude(28.8746)
                                    .build())
                            .contactNumber("0212 555 9876")
                            .workingHours("09:00-19:00 (Haftanın her günü)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.CREDIT_CARD, PaymentMethod.QR_CODE))
                            .active(true)
                            .build(),

                    // 6. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Ankara Kızılay Merkez")
                            .description("Kızılay'daki ana ödeme merkezi")
                            .address(Address.builder()
                                    .street("Kızılay Meydanı No:5")
                                    .district("Çankaya")
                                    .city("Ankara")
                                    .postalCode("06420")
                                    .build())
                            .location(Location.builder()
                                    .latitude(39.9208)
                                    .longitude(32.8541)
                                    .build())
                            .contactNumber("0312 555 1234")
                            .workingHours("08:30-17:30 (Hafta içi)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.CREDIT_CARD, PaymentMethod.CREDIT_CARD))
                            .active(true)
                            .build(),

                    // 7. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("İzmir Konak Ödeme Noktası")
                            .description("Konak meydanındaki ödeme noktası")
                            .address(Address.builder()
                                    .street("Konak Meydanı")
                                    .district("Konak")
                                    .city("İzmir")
                                    .postalCode("35260")
                                    .build())
                            .location(Location.builder()
                                    .latitude(38.4192)
                                    .longitude(27.1287)
                                    .build())
                            .contactNumber("0232 555 4567")
                            .workingHours("09:00-18:00 (Haftanın her günü)")
                            .paymentMethods(Arrays.asList(PaymentMethod.MOBILE_APP, PaymentMethod.CREDIT_CARD))
                            .active(true)
                            .build(),

                    // 8. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Bursa Kent Meydanı")
                            .description("Bursa kent meydanındaki ödeme noktası")
                            .address(Address.builder()
                                    .street("Kent Meydanı No:10")
                                    .district("Osmangazi")
                                    .city("Bursa")
                                    .postalCode("16010")
                                    .build())
                            .location(Location.builder()
                                    .latitude(40.1885)
                                    .longitude(29.0610)
                                    .build())
                            .contactNumber("0224 555 7890")
                            .workingHours("09:00-20:00 (Haftanın her günü)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.CREDIT_CARD))
                            .active(true)
                            .build(),

                    // 9. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Eskişehir Tramvay Durağı")
                            .description("Eskişehir tramvay durağındaki ödeme noktası")
                            .address(Address.builder()
                                    .street("Üniversite Durağı")
                                    .district("Tepebaşı")
                                    .city("Eskişehir")
                                    .postalCode("26040")
                                    .build())
                            .location(Location.builder()
                                    .latitude(39.7667)
                                    .longitude(30.5256)
                                    .build())
                            .contactNumber("0222 555 6543")
                            .workingHours("06:00-23:00 (Haftanın her günü)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CREDIT_CARD))
                            .active(true)
                            .build(),

                    // 10. Ödeme Noktası
                    PaymentPoint.builder()
                            .name("Antalya Konyaaltı")
                            .description("Konyaaltı plajı yakınındaki ödeme noktası")
                            .address(Address.builder()
                                    .street("Konyaaltı Caddesi No:123")
                                    .district("Konyaaltı")
                                    .city("Antalya")
                                    .postalCode("07070")
                                    .build())
                            .location(Location.builder()
                                    .latitude(36.8841)
                                    .longitude(30.7056)
                                    .build())
                            .contactNumber("0242 555 9876")
                            .workingHours("09:00-21:00 (Haftanın her günü)")
                            .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.CREDIT_CARD, PaymentMethod.QR_CODE))
                            .active(true)
                            .build()
            );

            paymentPointRepository.saveAll(paymentPoints);
            System.out.println("10 adet ödeme noktası veritabanına eklendi.");
        };
    }
}