package akin.city_card.initializer;

import akin.city_card.paymentPoint.model.Address;
import akin.city_card.paymentPoint.model.Location;
import akin.city_card.paymentPoint.model.PaymentMethod;
import akin.city_card.paymentPoint.model.PaymentPoint;
import akin.city_card.paymentPoint.repository.PaymentPointRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
@Order(11)
public class PaymentPointInitializer implements CommandLineRunner {

    private final PaymentPointRepository paymentPointRepository;

    @Override
    public void run(String... args) throws Exception {
        if (paymentPointRepository.count() > 0) {
            return;
        }

        List<PaymentPoint> paymentPoints = List.of(
                PaymentPoint.builder()
                        .name("Merkez Ödeme Noktası")
                        .location(new Location(40.998, 29.123))
                        .address(new Address("Atatürk Caddesi No:123", "Kadıköy", "İstanbul", "34000"))
                        .contactNumber("+90 216 123 45 67")
                        .workingHours("09:00 - 18:00")
                        .paymentMethods(Arrays.asList(PaymentMethod.CREDIT_CARD, PaymentMethod.CASH))
                        .description("Merkez şubemiz, haftanın 7 günü hizmet vermektedir.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Avrupa Yakası Ödeme Noktası")
                        .location(new Location(41.005, 28.976))
                        .address(new Address("İstiklal Caddesi No:45", "Beyoğlu", "İstanbul", "34430"))
                        .contactNumber("+90 212 987 65 43")
                        .workingHours("10:00 - 19:00")
                        .paymentMethods(Arrays.asList(PaymentMethod.CREDIT_CARD, PaymentMethod.DEBIT_CARD))
                        .description("Avrupa yakasındaki en büyük ödeme noktası.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Ankara Kızılay Ödeme Noktası")
                        .location(new Location(39.920, 32.854))
                        .address(new Address("Atatürk Bulvarı No:101", "Kızılay", "Ankara", "06420"))
                        .contactNumber("+90 312 456 78 90")
                        .workingHours("08:30 - 17:30")
                        .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.QR_CODE))
                        .description("Ankara'nın merkezi ödeme noktası.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("İzmir Konak Ödeme Merkezi")
                        .location(new Location(38.419, 27.128))
                        .address(new Address("Atatürk Caddesi No:3", "Konak", "İzmir", "35250"))
                        .contactNumber("+90 232 555 44 33")
                        .workingHours("09:00 - 18:00")
                        .paymentMethods(Arrays.asList(PaymentMethod.CREDIT_CARD, PaymentMethod.CASH, PaymentMethod.DEBIT_CARD))
                        .description("İzmir'in ana ödeme noktası.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Bursa Nilüfer Ödeme Noktası")
                        .location(new Location(40.182, 29.061))
                        .address(new Address("Nilüfer Caddesi No:15", "Nilüfer", "Bursa", "16120"))
                        .contactNumber("+90 224 123 45 67")
                        .workingHours("09:00 - 17:00")
                        .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.QR_CODE))
                        .description("Bursa'nın önemli ödeme noktası.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Antalya Lara Ödeme Merkezi")
                        .location(new Location(36.884, 30.701))
                        .address(new Address("Lara Caddesi No:78", "Lara", "Antalya", "07100"))
                        .contactNumber("+90 242 987 65 43")
                        .workingHours("10:00 - 20:00")
                        .paymentMethods(Arrays.asList(PaymentMethod.CREDIT_CARD, PaymentMethod.DEBIT_CARD))
                        .description("Antalya Lara bölgesinin ödeme merkezi.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Gaziantep Şahinbey Ödeme Noktası")
                        .location(new Location(37.061, 37.382))
                        .address(new Address("Şehit Kamil Caddesi No:12", "Şahinbey", "Gaziantep", "27010"))
                        .contactNumber("+90 342 123 45 67")
                        .workingHours("08:00 - 16:30")
                        .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.QR_CODE))
                        .description("Gaziantep Şahinbey bölgesindeki ödeme noktası.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Trabzon Merkez Ödeme Noktası")
                        .location(new Location(41.001, 39.717))
                        .address(new Address("Cumhuriyet Caddesi No:50", "Ortahisar", "Trabzon", "61000"))
                        .contactNumber("+90 462 555 66 77")
                        .workingHours("09:00 - 18:00")
                        .paymentMethods(Arrays.asList(PaymentMethod.CREDIT_CARD, PaymentMethod.CASH))
                        .description("Trabzon merkez ödeme noktası.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Konya Selçuklu Ödeme Merkezi")
                        .location(new Location(37.865, 32.484))
                        .address(new Address("Selçuk Caddesi No:22", "Selçuklu", "Konya", "42000"))
                        .contactNumber("+90 332 123 45 67")
                        .workingHours("09:00 - 17:00")
                        .paymentMethods(Arrays.asList(PaymentMethod.DEBIT_CARD, PaymentMethod.CASH))
                        .description("Konya Selçuklu bölgesindeki ödeme noktası.")
                        .active(true)
                        .build(),

                PaymentPoint.builder()
                        .name("Eskişehir Odunpazarı Ödeme Noktası")
                        .location(new Location(39.776, 30.520))
                        .address(new Address("Atatürk Caddesi No:8", "Odunpazarı", "Eskişehir", "26010"))
                        .contactNumber("+90 222 555 44 33")
                        .workingHours("08:30 - 17:30")
                        .paymentMethods(Arrays.asList(PaymentMethod.CASH, PaymentMethod.QR_CODE))
                        .description("Eskişehir Odunpazarı bölgesindeki ödeme noktası.")
                        .active(true)
                        .build()
        );

        paymentPointRepository.saveAll(paymentPoints);
        System.out.println(paymentPoints.size() + " adet ödeme noktası eklendi.");
    }
}
