package akin.city_card.initializer;

import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import akin.city_card.news.repository.NewsRepository;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.IntStream;

// ...

@Component
@RequiredArgsConstructor
public class UserDataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        createRandomUsers();
    }

    private void createRandomUsers() {
        if (userRepository.count() == 0) {
            List<User> users = IntStream.range(1, 11)
                    .mapToObj(this::generateRandomUser)
                    .toList();

            userRepository.saveAll(users);
            System.out.println(">> 10 adet örnek kullanıcı eklendi.");
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
                .deviceInfo(DeviceInfo.builder()
                        .deviceUuid("device-uuid-" + i)
                        .ipAddress("192.168.1." + i)
                        .fcmToken("token-" + i)
                        .build())
                .build();

        // identityInfo oluştur
        user.setIdentityInfo(UserIdentityInfo.builder()
                .user(user) // ilişkiyi kur
                .nationalId(generateNationalId(i)) // 11 haneli TC gibi
                .birthDate(LocalDate.of(1995, 1, (i % 28) + 1))
                .motherName("Anne" + i)
                .fatherName("Baba" + i)
                .gender(i % 2 == 0 ? "Erkek" : "Kadın")
                .serialNumber("A123456" + i)
                .approved(true)
                .approvedAt(LocalDateTime.now())
                .build());

        return user;
    }
    private String generateNationalId(int i) {
        return String.format("12345678%03d", i); // 11 haneli örnek
    }


    private String generatePhoneNumber(int i) {
        // i = 1 → +905330000001, i = 2 → +905330000002, ...
        return String.format("+905331%06d", i);
    }



}
