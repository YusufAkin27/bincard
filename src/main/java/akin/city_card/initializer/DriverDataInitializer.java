package akin.city_card.initializer;

import akin.city_card.driver.model.Driver;

import akin.city_card.driver.model.Shift;
import akin.city_card.driver.repository.DriverRepository;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.user.model.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;


@Component
@RequiredArgsConstructor
public class DriverDataInitializer implements ApplicationRunner {

    private final DriverRepository driverRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (driverRepository.count() == 0) {
            List<Driver> drivers = IntStream.range(1, 11).mapToObj(this::createDriver).toList();
            driverRepository.saveAll(drivers);
            System.out.println(">> 10 sürücü eklendi.");
        }
    }

    private Driver createDriver(int i) {
        return Driver.builder()
                .userNumber(generatePhoneNumber(i))
                .password(passwordEncoder.encode("123456"))
                .roles(Set.of(Role.DRIVER))
                .emailVerified(true)
                .phoneVerified(true)
                .status(UserStatus.ACTIVE)
                .profileInfo(ProfileInfo.builder()
                        .name("Sürücü" + i)
                        .surname("Soyad" + i)
                        .email("driver" + i + "@citycard.com")
                        .build())
                .deviceInfo(DeviceInfo.builder()
                        .deviceUuid("device-driver-" + i)
                        .ipAddress("10.10.0." + i)
                        .build())
                .nationalId(generateNationalId(i))
                .dateOfBirth(LocalDate.of(1985, 1, i))
                .licenseIssueDate(LocalDate.of(2010, 1, i))
                .licenseClass("D")
                .address("Sürücü Mah. No: " + i)
                .shift(i % 2 == 0 ? Shift.DAYTIME: Shift.NIGHT)
                .build();
    }
    private String generateNationalId(int i) {
        return String.format("12345678%03d", i); // 12345678001 → 11 karakter
    }
    private String generatePhoneNumber(int i) {
        return String.format("+905332%06d", 10 + i); // +905330000011, +905330000012, ...
    }
}
