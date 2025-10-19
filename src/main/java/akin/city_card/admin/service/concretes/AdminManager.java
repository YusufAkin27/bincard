package akin.city_card.admin.service.concretes;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.request.UpdateDeviceInfoRequest;
import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.LoginHistoryDTO;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.*;
import akin.city_card.admin.repository.AdminApprovalRequestRepository;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.admin.service.abstracts.AdminService;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.location.core.response.LocationDTO;
import akin.city_card.location.exceptions.NoLocationFoundException;
import akin.city_card.location.model.Location;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.Role;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.user.core.request.ChangePasswordRequest;
import akin.city_card.user.core.request.UpdateProfileRequest;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.UserStatus;
import akin.city_card.user.repository.LoginHistoryRepository;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminManager implements AdminService {
    private final SecurityUserRepository securityUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminRepository adminRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final AdminApprovalRequestRepository adminApprovalRequestRepository;
    private final AuditLogRepository auditLogRepository;
    private final ContractService contractService;

    @Override
    @Transactional
    public ResponseMessage signUp(CreateAdminRequest adminRequest, HttpServletRequest httpServletRequest) throws PhoneIsNotValidException, PhoneNumberAlreadyExistsException {
        if (!PhoneNumberFormatter.PhoneValid(adminRequest.getTelephone())) {
            throw new PhoneIsNotValidException();
        }

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(adminRequest.getTelephone());
        adminRequest.setTelephone(normalizedPhone);
        if (securityUserRepository.existsByUserNumber(adminRequest.getTelephone())) {
            throw new PhoneNumberAlreadyExistsException();
        }

        DeviceInfo deviceInfo = new DeviceInfo();


        ProfileInfo profileInfo = ProfileInfo.builder()
                .name(adminRequest.getName())
                .surname(adminRequest.getSurname())
                .email(adminRequest.getEmail())
                .build();

        Admin admin = Admin.builder()
                .roles(Collections.singleton(Role.ADMIN))
                .password(passwordEncoder.encode(adminRequest.getPassword()))
                .currentDeviceInfo(deviceInfo)
                .profileInfo(profileInfo)
                .userNumber(normalizedPhone)
                .superAdminApproved(false)
                .isDeleted(false)
                .status(UserStatus.ACTIVE)
                .phoneVerified(true)
                .emailVerified(false)
                .build();

        adminRepository.save(admin);

        String ipAddress = extractClientIp(httpServletRequest);
        String userAgent = httpServletRequest.getHeader("User-Agent");

        try {
            contractService.autoAcceptMandatoryContracts(admin, ipAddress, userAgent);
            log.info("Zorunlu sözleşmeler otomatik kabul edildi - Kullanıcı: {}", admin.getUsername());
        } catch (Exception e) {
            log.error("Zorunlu sözleşmeler otomatik kabul edilirken hata - Kullanıcı: {}", admin.getUsername(), e);
            // Sözleşme kabul hatası kullanıcı kaydını engellemez, sadece log'lanır
        }

        // Admin kayıt olduğunda logla

        createAuditLog(
                admin,
                ActionType.SIGN_UP,
                "Admin kayıt oldu",
                deviceInfo,
                null,                   // targetEntityId yok
                "SUPER_ADMIN",          // hedef entity türü
                null,                   // amount yok
                "{\"platform\":\"web\"}" // metadata örneği (opsiyonel)
        );


        // Admin onay talebi oluştur ve kaydet
        AdminApprovalRequest approvalRequest = AdminApprovalRequest.builder()
                .admin(admin)
                .status(ApprovalStatus.PENDING)
                .requestedAt(LocalDateTime.now())
                .build();

        adminApprovalRequestRepository.save(approvalRequest);

        return new ResponseMessage("Kayıt başarılı. Super admin onayı bekleniyor.", true);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp.trim();
        }

        return request.getRemoteAddr();
    }

    public void createAuditLog(SecurityUser user,
                               ActionType action,
                               String description,
                               DeviceInfo deviceInfo,
                               Long targetEntityId,
                               String targetEntityType,
                               Double amount,
                               String metadata) {

        AuditLog auditLog = new AuditLog();
        auditLog.setUser(user);
        auditLog.setAction(action);
        auditLog.setDescription(description);
        auditLog.setDeviceInfo(deviceInfo);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setTargetEntityId(targetEntityId);
        auditLog.setTargetEntityType(targetEntityType);
        auditLog.setAmount(amount);
        auditLog.setMetadata(metadata);

        auditLogRepository.save(auditLog);
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

        // ProfileInfo null olabilir, önce kontrol et
        if (admin.getProfileInfo() == null) {
            admin.setProfileInfo(new ProfileInfo());
        }

        ProfileInfo profile = admin.getProfileInfo();

        if (request.getName() != null && !request.getName().isBlank()) {
            profile.setName(request.getName().trim());
            updated = true;
        }

        if (request.getSurname() != null && !request.getSurname().isBlank()) {
            profile.setSurname(request.getSurname().trim());
            updated = true;
        }

        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            profile.setEmail(request.getEmail().trim().toLowerCase());
            updated = true;
        }

        if (!updated) {
            return new ResponseMessage("Güncellenecek herhangi bir veri bulunamadı.", false);
        }

        adminRepository.save(admin);

        return new ResponseMessage("Profil bilgileriniz başarıyla güncellendi.", true);
    }


    @Override
    public ResponseMessage updateDeviceInfo(UpdateDeviceInfoRequest request, String username) throws AdminNotFoundException {
        Admin admin = findByUserNumber(username);

        DeviceInfo deviceInfo = admin.getCurrentDeviceInfo();
        if (deviceInfo == null) {
            deviceInfo = new DeviceInfo();
        }

        boolean updated = false;

        if (request.getFcmToken() != null && !request.getFcmToken().isBlank()) {
            deviceInfo.setFcmToken(request.getFcmToken());
            updated = true;
        }


        if (request.getIpAddress() != null && !request.getIpAddress().isBlank()) {
            deviceInfo.setIpAddress(request.getIpAddress());
            updated = true;
        }

        if (!updated) {
            return new ResponseMessage("Güncellenecek cihaz bilgisi bulunamadı.", false);
        }

        admin.setCurrentDeviceInfo(deviceInfo);
        adminRepository.save(admin);

        return new ResponseMessage("Cihaz bilgileri başarıyla güncellendi.", true);
    }


    @Override
    public LocationDTO getLocation(String username) throws AdminNotFoundException, NoLocationFoundException {
        Admin admin = findByUserNumber(username);

        List<Location> locations = admin.getLocationHistory();
        if (locations == null || locations.isEmpty()) {
            throw new NoLocationFoundException();
        }

        Location latestLocation = locations.get(0);

        return LocationDTO.builder()
                .latitude(latestLocation.getLatitude())
                .longitude(latestLocation.getLongitude())
                .recordedAt(latestLocation.getRecordedAt())
                .userId(admin.getId())
                .build();
    }


    @Override
    public ResponseMessage updateLocation(UpdateLocationRequest request, String username) throws AdminNotFoundException {
        Admin admin = findByUserNumber(username);
        Location location = new Location();
        location.setLatitude(request.getLatitude());
        location.setLongitude(request.getLongitude());
        location.setRecordedAt(LocalDateTime.now());
        location.setUser(admin);
        admin.getLocationHistory().add(location);
        adminRepository.save(admin);
        return new ResponseMessage("Lokasyon güncellendi.", true);
    }

    @Override
    public DataResponseMessage<List<LoginHistoryDTO>> getLoginHistory(String username) throws AdminNotFoundException {
        Admin admin = findByUserNumber(username);

        List<LoginHistory> historyList = loginHistoryRepository.findAllByUserOrderByLoginAtDesc(admin);

        List<LoginHistoryDTO> responseList = historyList.stream()
                .map(login -> LoginHistoryDTO.builder()
                        .ipAddress(login.getIpAddress())
                        .device(login.getDevice())
                        .platform(login.getPlatform())
                        .appVersion(login.getAppVersion())
                        .loginAt(login.getLoginAt())
                        .build())
                .toList();

        return new DataResponseMessage<>("Giriş geçmişi başarıyla getirildi.", true, responseList);
    }


}
