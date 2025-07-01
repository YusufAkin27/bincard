package akin.city_card.admin.service.concretes;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.request.UpdateDeviceInfoRequest;
import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.LoginHistoryDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.service.abstracts.AdminService;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.Role;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.sms.SmsService;
import akin.city_card.user.core.request.ChangePasswordRequest;
import akin.city_card.user.core.request.UpdateProfileRequest;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import akin.city_card.verification.repository.VerificationCodeRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminManager implements AdminService {
    private final SecurityUserRepository securityUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final SmsService smsService;
    private final AdminRepository adminRepository;

    private final VerificationCodeRepository verificationCodeRepository;

    @Override
    @Transactional
    public ResponseMessage signUp(CreateAdminRequest adminRequest) throws PhoneIsNotValidException, PhoneNumberAlreadyExistsException {
        // Telefon kontrolü
        if (!PhoneNumberFormatter.PhoneValid(adminRequest.getTelephone())) {
            throw new PhoneIsNotValidException();
        }

        if (securityUserRepository.existsByUserNumber(adminRequest.getTelephone())) {
            throw new PhoneNumberAlreadyExistsException();
        }

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(adminRequest.getTelephone());
        adminRequest.setTelephone(normalizedPhone);

        Admin admin = Admin.builder()
                .roles(Collections.singleton(Role.ADMIN))
                .password(passwordEncoder.encode(adminRequest.getPassword()))
                .ipAddress(adminRequest.getIpAddress())
                .deviceUuid(adminRequest.getDeviceUuid())
                .userNumber(adminRequest.getTelephone())
                .superAdminApproved(true) // Eğer super admin onayı gerekiyorsa false olmalı
                .isDeleted(false)
                .isActive(true)
                .name(adminRequest.getName()) // Placeholder, frontend üzerinden alınmalı
                .surname(adminRequest.getSurname()) // Placeholder, frontend üzerinden alınmalı
                .email(adminRequest.getEmail()) // opsiyonel olarak frontend'den alınabilir
                .phoneVerified(true)
                .emailVerified(false)
                .lastLoginDevice(adminRequest.getUserAgent())
                .build();

        // Kaydet
        adminRepository.save(admin);

        return new ResponseMessage("Kayıt başarılı. Super admin onayı bekleniyor.", true);
    }

    @Override
    @Transactional
    public ResponseMessage changePassword(ChangePasswordRequest request, String username)
            throws AdminNotFoundException, PasswordTooShortException, PasswordSameAsOldException, IncorrectCurrentPasswordException {

        Admin admin = findByUserNumber(username);

        if (request.getNewPassword().length() != 6) {
            throw new PasswordTooShortException();
        }

        if (passwordEncoder.matches(request.getNewPassword(), admin.getPassword())) {
            throw new PasswordSameAsOldException();
        }

        if (!passwordEncoder.matches(request.getCurrentPassword(), admin.getPassword())) {
            throw new IncorrectCurrentPasswordException();
        }

        admin.setPassword(passwordEncoder.encode(request.getNewPassword()));
        adminRepository.save(admin);

        return new ResponseMessage("Şifreniz başarıyla güncellendi.", true);
    }


    public Admin findByUserNumber(String username) throws AdminNotFoundException {
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            throw new AdminNotFoundException();
        }
        return admin;

    }

    @Override
    @Transactional
    public ResponseMessage updateProfile(UpdateProfileRequest request, String username) throws AdminNotFoundException {
        Admin admin = findByUserNumber(username);

        boolean updated = false;

        if (request.getName() != null && !request.getName().isBlank()) {
            admin.setName(request.getName().trim());
            updated = true;
        }

        if (request.getSurname() != null && !request.getSurname().isBlank()) {
            admin.setSurname(request.getSurname().trim());
            updated = true;
        }
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            admin.setEmail(request.getEmail().trim().toLowerCase());
            updated = true;
        }

        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            if (request.getPassword().length() < 6) {
                return new ResponseMessage("Şifre en az 6 karakter olmalıdır.",true);
            }
            admin.setPassword(passwordEncoder.encode(request.getPassword()));
            updated = true;
        }

        if (!updated) {
            return new ResponseMessage("Güncellenicek hiç bir veri bulunamadı", false);
        }

        adminRepository.save(admin);

        return new ResponseMessage("Profil bilgileriniz başarıyla güncellendi.",true);
    }


    @Override
    public ResponseMessage updateDeviceInfo(UpdateDeviceInfoRequest request, String username) {
        return null;
    }

    @Override
    public ResponseMessage getLocation(String username) {
        return null;
    }

    @Override
    public ResponseMessage updateLocation(UpdateLocationRequest request, String username) {
        return null;
    }

    @Override
    public DataResponseMessage<List<LoginHistoryDTO>> getLoginHistory(String username) {
        return null;
    }


}
