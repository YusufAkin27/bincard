package akin.city_card;

import akin.city_card.security.entity.Role;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
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

        SuperAdmin superAdmin = new SuperAdmin();
        superAdmin.setUserNumber(defaultPhone);
        superAdmin.setPassword(passwordEncoder.encode(defaultPassword));
        superAdmin.setRoles(Set.of(Role.SUPERADMIN, Role.ADMIN, Role.USER, Role.DRVIER)); // Roller
        superAdmin.setActive(true);
        superAdmin.setDeleted(false);

        // Zorunlu alanlar:
        superAdmin.setName("Super");
        superAdmin.setSurname("Admin");

        // Opsiyonel ama varsa doldurulabilir:
        superAdmin.setEmail("superadmin@example.com");
        superAdmin.setEmailVerified(true);
        superAdmin.setPhoneVerified(true);

        superAdminRepository.save(superAdmin);

        System.out.println("🚀 SuperAdmin başarıyla oluşturuldu → " + defaultPhone + " / " + defaultPassword);
    }
}
