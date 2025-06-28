package akin.city_card.admin.service.concretes;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.service.abstracts.AdminService;
import akin.city_card.user.exceptions.PhoneIsNotValidException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.Role;
import akin.city_card.sms.SmsService;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import akin.city_card.verification.repository.VerificationCodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AdminManager implements AdminService {
    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;
    private final SmsService smsService;

    private final VerificationCodeRepository  verificationCodeRepository;
    @Override
    public ResponseMessage signUp(CreateAdminRequest adminRequest) throws PhoneIsNotValidException, PhoneNumberAlreadyExistsException {
        if (!PhoneNumberFormatter.PhoneValid(adminRequest.getTelephone())){
            throw new PhoneIsNotValidException();
        }
        if (!adminRepository.existsByUserNumber(adminRequest.getTelephone())){
            throw new PhoneNumberAlreadyExistsException();
        }
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(adminRequest.getTelephone());
        adminRequest.setTelephone(normalizedPhone);



        Admin admin = Admin.builder()
                .roles(Collections.singleton(Role.ADMIN))
                .password(passwordEncoder.encode(adminRequest.getPassword()))
                .ipAddress(adminRequest.getIpAddress())
                .isDeleted(false)
                .isActive(true)
                .userNumber(adminRequest.getTelephone())
                .deviceUuid(adminRequest.getDeviceUuid())
                .superAdminApproved(true) // onaylanmamış başvuru
                .build();

        // Kayıt
        adminRepository.save(admin);

        return new ResponseMessage("Kayıt başarılı. Super admin onayı bekleniyor.", true);
    }



}
