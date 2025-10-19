package akin.city_card.initializer;

import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.contract.core.request.AcceptContractRequest;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.service.abstacts.ContractService;
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

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.IntStream;

@Component
@RequiredArgsConstructor
@Order(6)
public class AdminDataInitializer implements ApplicationRunner {

    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;
    private final ContractService contractService;


    @Override
    public void run(ApplicationArguments args) {
        List<Admin> adminsToSave = IntStream.range(1, 11)
                .mapToObj(this::generateAdmin)
                .filter(Objects::nonNull) // null olanları çıkar
                .toList();

        if (!adminsToSave.isEmpty()) {
            adminRepository.saveAll(adminsToSave);
            System.out.println(">> " + adminsToSave.size() + " yeni admin eklendi.");

            for (Admin admin : adminsToSave) {
                try {
                    List<UserContractDTO> mandatoryContracts = contractService.getMandatoryContractsForUser(admin.getUserNumber());

                    for (UserContractDTO contract : mandatoryContracts) {
                        AcceptContractRequest request = new AcceptContractRequest();
                        request.setAccepted(true);
                        request.setIpAddress(admin.getCurrentDeviceInfo().getIpAddress());
                        request.setUserAgent("AdminDataInitializer/1.0");
                        request.setContractVersion(contract.getVersion());

                        contractService.acceptContract(admin.getUserNumber(), contract.getId(), request);
                    }
                } catch (Exception e) {
                }
            }
        } else {
        }
    }


    private Admin generateAdmin(int i) {
        String phoneNumber = generatePhoneNumber(i); // Örn: +905333000011
        if (adminRepository.findByUserNumber(phoneNumber) != null) {
            return null;
        }

        return Admin.builder()
                .userNumber(phoneNumber)
                .password(passwordEncoder.encode("123456"))
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
                .currentDeviceInfo(DeviceInfo.builder()
                        .ipAddress("10.0.0." + i)
                        .fcmToken("admintoken-" + i)
                        .build())
                .build();
    }

    private String generatePhoneNumber(int i) {
        return String.format("+905333%06d", 20 + i); // +905330000011, +905330000012, ...
    }

}
