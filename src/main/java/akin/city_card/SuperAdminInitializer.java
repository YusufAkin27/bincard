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
        String defaultPhone = "5550000000";
        String defaultPassword = "superadmin";

        boolean exists = superAdminRepository.findByUserNumber(defaultPhone).isPresent();

        if (exists) {
            System.out.println("✅ SuperAdmin zaten mevcut.");
            return;
        }

        SuperAdmin superAdmin = new SuperAdmin();
        superAdmin.setUserNumber(defaultPhone);
        superAdmin.setPassword(passwordEncoder.encode(defaultPassword));
        superAdmin.setRoles(Set.of(Role.SUPERADMIN)); // Enum içeriği varsa
        superAdmin.setActive(true);
        superAdmin.setDeleted(false);

        superAdminRepository.save(superAdmin);

        System.out.println("🚀 SuperAdmin başarıyla oluşturuldu → " + defaultPhone + " / " + defaultPassword);
    }
}
