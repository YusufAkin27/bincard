package akin.city_card.initializer;

import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.user.model.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class SuperAdminInitializer implements CommandLineRunner {

    private final SuperAdminRepository superAdminRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        String defaultPhone = "+905550000000";
        String defaultPassword = "123456";

        SuperAdmin exists = superAdminRepository.findByUserNumber(defaultPhone);
        if (exists != null) {
            System.out.println("✅ SuperAdmin zaten mevcut.");
            return;
        }

        // Yeni profil bilgisi oluştur
        ProfileInfo profileInfo = ProfileInfo.builder()
                .name("Super")
                .surname("Admin")
                .email("superadmin@example.com")
                .build();

        SuperAdmin superAdmin = new SuperAdmin();
        superAdmin.setUserNumber(defaultPhone);
        superAdmin.setPassword(passwordEncoder.encode(defaultPassword));
        superAdmin.setRoles(Set.of(Role.SUPERADMIN, Role.ADMIN, Role.USER, Role.DRIVER));
        superAdmin.setStatus(UserStatus.ACTIVE);
        superAdmin.setDeleted(false);
        superAdmin.setProfileInfo(profileInfo);
        superAdmin.setEmailVerified(true);
        superAdmin.setPhoneVerified(true);

        superAdminRepository.save(superAdmin);

        System.out.println("🚀 SuperAdmin başarıyla oluşturuldu → " + defaultPhone + " / " + defaultPassword);
    }

}
