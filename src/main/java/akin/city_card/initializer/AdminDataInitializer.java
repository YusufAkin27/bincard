package akin.city_card.initializer;

import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.user.model.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.IntStream;

@Component
@RequiredArgsConstructor
public class AdminDataInitializer implements ApplicationRunner {

    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;
    private static final Random random = new Random();

    @Override
    public void run(ApplicationArguments args) {
        if (adminRepository.count() == 0) {
            List<Admin> admins = IntStream.range(1, 11)
                    .mapToObj(this::generateAdmin)
                    .toList();

            adminRepository.saveAll(admins);
            System.out.println(">> 10 adet admin eklendi.");
        }
    }

    private Admin generateAdmin(int i) {
        String phoneNumber = generatePhoneNumber(i); // +905330000011, +905330000012, ...

        return Admin.builder()
                .userNumber(phoneNumber)
                .password(passwordEncoder.encode("123456")) // Gerçek uygulamada hashlenmeli
                .roles(Set.of(Role.ADMIN))
                .status(UserStatus.ACTIVE)
                .isDeleted(false)
                .emailVerified(true)
                .phoneVerified(true)
                .superAdminApproved(true)
                .approvedAt(java.time.LocalDateTime.now())
                .profileInfo(ProfileInfo.builder()
                        .name("Admin" + i)
                        .surname("Yetkili" + i)
                        .email("admin" + i + "@citycard.com")
                        .profilePicture("https://example.com/admin" + i + ".jpg")
                        .build())
                .deviceInfo(DeviceInfo.builder()
                        .deviceUuid("admin-device-" + i)
                        .ipAddress("10.0.0." + i)
                        .fcmToken("admintoken-" + i)
                        .build())
                .build();
    }

    private String generatePhoneNumber(int i) {
        return String.format("+905333%06d", 10 + i); // +905330000011, +905330000012, ...
    }

}
