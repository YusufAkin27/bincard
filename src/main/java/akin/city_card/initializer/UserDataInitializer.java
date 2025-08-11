package akin.city_card.initializer;

import akin.city_card.contract.core.request.AcceptContractRequest;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.user.model.User;
import akin.city_card.user.model.UserIdentityInfo;
import akin.city_card.user.model.UserStatus;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;

@Component
@RequiredArgsConstructor
@Order(3)  // Üçüncü sırada
public class UserDataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ContractService contractService;

    @Override
    @Transactional  // Transaction eklendi
    public void run(ApplicationArguments args) {
        if (userRepository.count() == 0) {
            List<User> users = IntStream.range(1, 11)
                    .mapToObj(this::generateRandomUser)
                    .toList();

            userRepository.saveAll(users);
            System.out.println(">> 10 adet örnek kullanıcı eklendi.");

            // Zorunlu sözleşmeleri kabul ettir
            for (User user : users) {
                try {
                    List<UserContractDTO> mandatoryContracts = contractService.getMandatoryContractsForUser(user.getUserNumber());

                    for (UserContractDTO contract : mandatoryContracts) {
                        AcceptContractRequest request = new AcceptContractRequest();
                        request.setAccepted(true);
                        request.setIpAddress(user.getCurrentDeviceInfo().getIpAddress());
                        request.setUserAgent("UserDataInitializer/1.0");
                        request.setContractVersion(contract.getVersion());

                        contractService.acceptContract(user.getUserNumber(), contract.getId(), request);
                    }

                } catch (Exception e) {
                    System.err.println(">> Kullanıcı " + user.getUserNumber() + " için sözleşme kabul hatası: " + e.getMessage());
                }
            }
        }
    }

    private User generateRandomUser(int i) {
        String phoneNumber = generatePhoneNumber(i);

        User user = User.builder()
                .userNumber(phoneNumber)
                .password(passwordEncoder.encode("123456"))
                .roles(Set.of(Role.USER))
                .status(UserStatus.ACTIVE)
                .isDeleted(false)
                .emailVerified(true)
                .phoneVerified(true)
                .negativeBalanceLimit(0.0)
                .walletActivated(true)
                .profileInfo(ProfileInfo.builder()
                        .name("Ad" + i)
                        .surname("Soyad" + i)
                        .email("user" + i + "@example.com")
                        .profilePicture("https://example.com/profile" + i + ".jpg")
                        .build())
                .currentDeviceInfo(DeviceInfo.builder()
                        .ipAddress("192.168.1." + i)
                        .fcmToken("token-" + i)
                        .build())
                .build();

        // identityInfo oluştur ve user ile ilişkilendir
        UserIdentityInfo identityInfo = UserIdentityInfo.builder()
                .user(user) // İlişkiyi kur
                .nationalId(generateNationalId(i))
                .birthDate(LocalDate.of(1995, 1, (i % 28) + 1))
                .motherName("Anne" + i)
                .fatherName("Baba" + i)
                .gender(i % 2 == 0 ? "Erkek" : "Kadın")
                .serialNumber("A123456" + i)
                .approved(true)
                .approvedAt(LocalDateTime.now())
                .build();

        user.setIdentityInfo(identityInfo);

        return user;
    }

    private String generateNationalId(int i) {
        return String.format("12345678%03d", i); // 11 haneli örnek
    }

    private String generatePhoneNumber(int i) {
        return String.format("+905331%06d", i);
    }
}
