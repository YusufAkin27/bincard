package akin.city_card.initializer;

import akin.city_card.contract.core.request.AcceptContractRequest;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.service.abstacts.ContractService;
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
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.IntStream;


@Component
@RequiredArgsConstructor
@Order(5)
public class DriverDataInitializer implements ApplicationRunner {

    private final DriverRepository driverRepository;
    private final PasswordEncoder passwordEncoder;
    private final Random random = new Random();
    private final ContractService contractService;

    @Override
    public void run(ApplicationArguments args) {
        if (driverRepository.count() == 0) {
            List<Driver> drivers = IntStream.range(0, 100)
                    .mapToObj(this::createDriver)
                    .toList();

            driverRepository.saveAll(drivers);
            System.out.println(">> 100 sürücü eklendi.");

            // Sözleşmeleri kabul ettir
            for (Driver driver : drivers) {
                try {
                    List<UserContractDTO> mandatoryContracts = contractService.getMandatoryContractsForUser(driver.getUserNumber());

                    for (UserContractDTO contract : mandatoryContracts) {
                        AcceptContractRequest request = new AcceptContractRequest();
                        request.setAccepted(true);
                        request.setIpAddress(driver.getCurrentDeviceInfo().getIpAddress());
                        request.setUserAgent("DriverDataInitializer/1.0");
                        request.setContractVersion(contract.getVersion());

                        contractService.acceptContract(driver.getUserNumber(), contract.getId(), request);
                    }

                } catch (Exception e) {
                    System.err.println(">> Sürücü " + driver.getUserNumber() + " için sözleşme kabul hatası: " + e.getMessage());
                }
            }
        }
    }

    private Driver createDriver(int i) {
        int safeDay = (i % 28) + 1;

        return Driver.builder()
                .userNumber(generatePhoneNumber(i))
                .password(passwordEncoder.encode("123456"))
                .roles(Set.of(Role.DRIVER))
                .emailVerified(true)
                .phoneVerified(true)
                .status(UserStatus.ACTIVE)
                .cardUid(String.valueOf(53327706)+i)
                .active(true)
                .assignedBus(null)
                .profileInfo(ProfileInfo.builder()
                        .name("Sürücü" + i)
                        .surname("Soyad" + i)
                        .email("driver" + i + "@citycard.com")
                        .build())
                .currentDeviceInfo(DeviceInfo.builder()
                        .ipAddress("10.10.0." + i)
                        .build())
                .nationalId(generateNationalId(i))
                .dateOfBirth(LocalDate.of(1985, 1, safeDay))
                .licenseIssueDate(LocalDate.of(2010, 1, safeDay))
                .licenseClass("D")
                .address("Sürücü Mah. No: " + i)
                .shift(i % 2 == 0 ? Shift.DAYTIME : Shift.NIGHT)
                .build();
    }

    private String generateNationalId(int i) {
        return String.format("12345678%03d", i);
    }

    private String generatePhoneNumber(int i) {
        return String.format("+905332%06d", 10 + i);
    }
}