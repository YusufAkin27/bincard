package akin.city_card.initializer;

import akin.city_card.contract.core.request.AcceptContractRequest;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.user.model.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
@Order(2)
public class SuperAdminInitializer implements CommandLineRunner {

    private final SuperAdminRepository superAdminRepository;
    private final PasswordEncoder passwordEncoder;
    private final ContractService contractService;

    @Override
    public void run(String... args) {
        String defaultPhone = "+905550000000";
        String defaultPassword = "123456";

        SuperAdmin exists = superAdminRepository.findByUserNumber(defaultPhone);
        if (exists != null) {
            System.out.println("✅ SuperAdmin zaten mevcut.");
            return;
        }

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

        // Zorunlu sözleşmeleri kabul ettir
        try {
            var contracts = contractService.getMandatoryContractsForUser(superAdmin.getUserNumber());

            for (UserContractDTO contract : contracts) {
                AcceptContractRequest request = new AcceptContractRequest();
                request.setAccepted(true);
                request.setIpAddress("127.0.0.1");
                request.setUserAgent("SuperAdminInitializer/1.0");
                request.setContractVersion(contract.getVersion());

                contractService.acceptContract(superAdmin.getUserNumber(), contract.getId(), request);
            }

            System.out.println("📄 SuperAdmin için tüm zorunlu sözleşmeler kabul edildi.");
        } catch (Exception e) {
            System.err.println("❌ SuperAdmin sözleşme kabul hatası: " + e.getMessage());
        }
    }

}
