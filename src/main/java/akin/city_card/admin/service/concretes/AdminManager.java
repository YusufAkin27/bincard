package akin.city_card.admin.service.concretes;

import akin.city_card.admin.core.converter.AuditLogConverter;
import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.core.request.UpdateDeviceInfoRequest;
import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.AdminDTO;
import akin.city_card.admin.core.response.AuditLogDTO;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
    private final AuditLogConverter auditLogConverter;
    private final ContractService contractService;

    @Override
    @Transactional
    public ResponseMessage signUp(CreateAdminRequest adminRequest, HttpServletRequest httpServletRequest) throws PhoneIsNotValidException, PhoneNumberAlreadyExistsException {
        log.debug("AdminManager.signUp - Method called with telephone: {}, name: {}, email: {}", 
                adminRequest.getTelephone(), adminRequest.getName(), adminRequest.getEmail());
        
        try {
            if (!PhoneNumberFormatter.PhoneValid(adminRequest.getTelephone())) {
                log.warn("AdminManager.signUp - Invalid phone number: {}", adminRequest.getTelephone());
                throw new PhoneIsNotValidException();
            }

            String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(adminRequest.getTelephone());
            adminRequest.setTelephone(normalizedPhone);
            log.debug("AdminManager.signUp - Normalized phone: {}", normalizedPhone);
            
            if (securityUserRepository.existsByUserNumber(adminRequest.getTelephone())) {
                log.warn("AdminManager.signUp - Phone number already exists: {}", normalizedPhone);
                throw new PhoneNumberAlreadyExistsException();
            }

            String ipAddress = extractClientIp(httpServletRequest);
            String userAgent = httpServletRequest.getHeader("User-Agent");
            log.debug("AdminManager.signUp - IP: {}, UserAgent: {}", ipAddress, userAgent);

            DeviceInfo deviceInfo = new DeviceInfo();
            deviceInfo.setIpAddress(ipAddress);
            if (userAgent != null) {
                deviceInfo.setUserAgent(userAgent);
            }

            ProfileInfo profileInfo = ProfileInfo.builder()
                    .name(adminRequest.getName())
                    .surname(adminRequest.getSurname())
                    .email(adminRequest.getEmail())
                    .build();

            Admin admin = Admin.builder()
                    .roles(Collections.singleton(Role.ADMIN_ALL))
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
            log.info("AdminManager.signUp - Admin created with ID: {}, telephone: {}", admin.getId(), normalizedPhone);

            try {
                contractService.autoAcceptMandatoryContracts(admin, ipAddress, userAgent);
                log.info("AdminManager.signUp - Zorunlu sözleşmeler otomatik kabul edildi - Kullanıcı: {}", admin.getUsername());
            } catch (Exception e) {
                log.error("AdminManager.signUp - Zorunlu sözleşmeler otomatik kabul edilirken hata - Kullanıcı: {}", admin.getUsername(), e);
                // Sözleşme kabul hatası kullanıcı kaydını engellemez, sadece log'lanır
            }

            // Admin kayıt olduğunda audit log oluştur
            String metadata = String.format("{\"platform\":\"web\",\"ipAddress\":\"%s\",\"userAgent\":\"%s\",\"name\":\"%s\",\"surname\":\"%s\"}", 
                    ipAddress, userAgent != null ? userAgent : "unknown", adminRequest.getName(), adminRequest.getSurname());
            
            createAuditLog(
                    admin,
                    ActionType.SIGN_UP,
                    String.format("Admin kayıt oldu: %s %s (%s)", adminRequest.getName(), adminRequest.getSurname(), normalizedPhone),
                    deviceInfo,
                    admin.getId(),
                    "ADMIN",
                    null,
                    metadata
            );

            // Admin onay talebi oluştur ve kaydet
            AdminApprovalRequest approvalRequest = AdminApprovalRequest.builder()
                    .admin(admin)
                    .status(ApprovalStatus.PENDING)
                    .requestedAt(LocalDateTime.now())
                    .build();

            adminApprovalRequestRepository.save(approvalRequest);
            log.info("AdminManager.signUp - Approval request created for admin ID: {}", admin.getId());

            return new ResponseMessage("Kayıt başarılı. Super admin onayı bekleniyor.", true);
        } catch (PhoneIsNotValidException | PhoneNumberAlreadyExistsException e) {
            log.error("AdminManager.signUp - Validation error for telephone: {}, Error: {}", adminRequest.getTelephone(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.signUp - Unexpected error for telephone: {}", adminRequest.getTelephone(), e);
            throw e;
        }
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
                               BigDecimal amount,
                               String metadata) {
        log.debug("AdminManager.createAuditLog - Creating audit log for user: {}, action: {}, description: {}", 
                user != null ? user.getUsername() : "null", action, description);
        
        try {
            // DeviceInfo null kontrolü ve oluşturma
            DeviceInfo logDeviceInfo = deviceInfo;
            if (logDeviceInfo == null && user != null) {
                logDeviceInfo = user.getCurrentDeviceInfo();
                if (logDeviceInfo == null) {
                    logDeviceInfo = new DeviceInfo();
                    log.warn("AdminManager.createAuditLog - DeviceInfo was null, created new one for user: {}", user.getUsername());
                }
            } else if (logDeviceInfo == null) {
                logDeviceInfo = new DeviceInfo();
                log.warn("AdminManager.createAuditLog - DeviceInfo was null, created new one");
            }

            AuditLog auditLog = new AuditLog();
            auditLog.setUser(user);
            auditLog.setAction(action);
            auditLog.setDescription(description);
            auditLog.setDeviceInfo(logDeviceInfo);
            auditLog.setTimestamp(LocalDateTime.now());
            auditLog.setTargetEntityId(targetEntityId);
            auditLog.setTargetEntityType(targetEntityType != null ? targetEntityType : "UNKNOWN");
            auditLog.setAmount(amount);
            auditLog.setMetadata(metadata != null ? metadata : "{}");

            auditLogRepository.save(auditLog);
            log.debug("AdminManager.createAuditLog - Audit log saved successfully for user: {}, action: {}", 
                    user != null ? user.getUsername() : "null", action);
        } catch (Exception e) {
            log.error("AdminManager.createAuditLog - Error creating audit log for user: {}, action: {}", 
                    user != null ? user.getUsername() : "null", action, e);
            // Audit log hatası işlemi engellemez
        }
    }


    @Override
    @Transactional
    public ResponseMessage changePassword(ChangePasswordRequest request, String username)
            throws AdminNotFoundException, PasswordTooShortException, PasswordSameAsOldException, IncorrectCurrentPasswordException {
        log.debug("AdminManager.changePassword - Method called for user: {}", username);
        
        try {
            Admin admin = findByUserNumber(username);
            log.debug("AdminManager.changePassword - Admin found with ID: {}", admin.getId());

            if (request.getNewPassword().length() != 6) {
                log.warn("AdminManager.changePassword - Password too short for user: {}", username);
                throw new PasswordTooShortException();
            }

            if (passwordEncoder.matches(request.getNewPassword(), admin.getPassword())) {
                log.warn("AdminManager.changePassword - New password same as old password for user: {}", username);
                throw new PasswordSameAsOldException();
            }

            if (!passwordEncoder.matches(request.getCurrentPassword(), admin.getPassword())) {
                log.warn("AdminManager.changePassword - Incorrect current password for user: {}", username);
                throw new IncorrectCurrentPasswordException();
            }

            admin.setPassword(passwordEncoder.encode(request.getNewPassword()));
            adminRepository.save(admin);
            log.info("AdminManager.changePassword - Password updated successfully for user: {}", username);

            // Audit log oluştur
            DeviceInfo deviceInfo = admin.getCurrentDeviceInfo() != null ? admin.getCurrentDeviceInfo() : new DeviceInfo();
            String metadata = String.format("{\"action\":\"password_change\",\"timestamp\":\"%s\"}", LocalDateTime.now());
            createAuditLog(
                    admin,
                    ActionType.CHANGE_PASSWORD,
                    "Admin şifresini değiştirdi",
                    deviceInfo,
                    admin.getId(),
                    "ADMIN",
                    null,
                    metadata
            );

            return new ResponseMessage("Şifreniz başarıyla güncellendi.", true);
        } catch (AdminNotFoundException | PasswordTooShortException | PasswordSameAsOldException | IncorrectCurrentPasswordException e) {
            log.error("AdminManager.changePassword - Error for user: {}, Error: {}", username, e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.changePassword - Unexpected error for user: {}", username, e);
            throw e;
        }
    }


    public Admin findByUserNumber(String username) throws AdminNotFoundException {
        log.debug("AdminManager.findByUserNumber - Searching for admin with username: {}", username);
        Admin admin = adminRepository.findByUserNumber(username);
        if (admin == null) {
            log.warn("AdminManager.findByUserNumber - Admin not found with username: {}", username);
            throw new AdminNotFoundException();
        }
        log.debug("AdminManager.findByUserNumber - Admin found with ID: {}", admin.getId());
        return admin;
    }

    @Override
    @Transactional
    public ResponseMessage updateProfile(UpdateProfileRequest request, String username) throws AdminNotFoundException {
        log.debug("AdminManager.updateProfile - Method called for user: {}, name: {}, surname: {}, email: {}", 
                username, request.getName(), request.getSurname(), request.getEmail());
        
        try {
            Admin admin = findByUserNumber(username);
            log.debug("AdminManager.updateProfile - Admin found with ID: {}", admin.getId());

            boolean updated = false;
            String oldName = null, oldSurname = null, oldEmail = null;

            // ProfileInfo null olabilir, önce kontrol et
            if (admin.getProfileInfo() == null) {
                admin.setProfileInfo(new ProfileInfo());
                log.debug("AdminManager.updateProfile - Created new ProfileInfo for admin ID: {}", admin.getId());
            }

            ProfileInfo profile = admin.getProfileInfo();

            if (request.getName() != null && !request.getName().isBlank()) {
                oldName = profile.getName();
                profile.setName(request.getName().trim());
                updated = true;
                log.debug("AdminManager.updateProfile - Name updated from '{}' to '{}'", oldName, request.getName());
            }

            if (request.getSurname() != null && !request.getSurname().isBlank()) {
                oldSurname = profile.getSurname();
                profile.setSurname(request.getSurname().trim());
                updated = true;
                log.debug("AdminManager.updateProfile - Surname updated from '{}' to '{}'", oldSurname, request.getSurname());
            }

            if (request.getEmail() != null && !request.getEmail().isBlank()) {
                oldEmail = profile.getEmail();
                profile.setEmail(request.getEmail().trim().toLowerCase());
                updated = true;
                log.debug("AdminManager.updateProfile - Email updated from '{}' to '{}'", oldEmail, request.getEmail());
            }

            if (!updated) {
                log.warn("AdminManager.updateProfile - No data to update for user: {}", username);
                return new ResponseMessage("Güncellenecek herhangi bir veri bulunamadı.", false);
            }

            adminRepository.save(admin);
            log.info("AdminManager.updateProfile - Profile updated successfully for user: {}", username);

            // Audit log oluştur
            DeviceInfo deviceInfo = admin.getCurrentDeviceInfo() != null ? admin.getCurrentDeviceInfo() : new DeviceInfo();
            String metadata = String.format("{\"oldName\":\"%s\",\"newName\":\"%s\",\"oldSurname\":\"%s\",\"newSurname\":\"%s\",\"oldEmail\":\"%s\",\"newEmail\":\"%s\"}", 
                    oldName != null ? oldName : "", request.getName() != null ? request.getName() : "",
                    oldSurname != null ? oldSurname : "", request.getSurname() != null ? request.getSurname() : "",
                    oldEmail != null ? oldEmail : "", request.getEmail() != null ? request.getEmail() : "");
            createAuditLog(
                    admin,
                    ActionType.UPDATE_PROFILE,
                    String.format("Admin profil bilgilerini güncelledi: %s", username),
                    deviceInfo,
                    admin.getId(),
                    "ADMIN",
                    null,
                    metadata
            );

            return new ResponseMessage("Profil bilgileriniz başarıyla güncellendi.", true);
        } catch (AdminNotFoundException e) {
            log.error("AdminManager.updateProfile - Admin not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.updateProfile - Unexpected error for user: {}", username, e);
            throw e;
        }
    }


    @Override
    public ResponseMessage updateDeviceInfo(UpdateDeviceInfoRequest request, String username) throws AdminNotFoundException {
        log.debug("AdminManager.updateDeviceInfo - Method called for user: {}, IP: {}, FCM: {}", 
                username, request.getIpAddress(), request.getFcmToken() != null ? "provided" : "not provided");
        
        try {
            Admin admin = findByUserNumber(username);
            log.debug("AdminManager.updateDeviceInfo - Admin found with ID: {}", admin.getId());

            DeviceInfo deviceInfo = admin.getCurrentDeviceInfo();
            if (deviceInfo == null) {
                deviceInfo = new DeviceInfo();
                log.debug("AdminManager.updateDeviceInfo - Created new DeviceInfo for admin ID: {}", admin.getId());
            }

            boolean updated = false;

            if (request.getFcmToken() != null && !request.getFcmToken().isBlank()) {
                deviceInfo.setFcmToken(request.getFcmToken());
                updated = true;
                log.debug("AdminManager.updateDeviceInfo - FCM token updated for user: {}", username);
            }

            if (request.getIpAddress() != null && !request.getIpAddress().isBlank()) {
                deviceInfo.setIpAddress(request.getIpAddress());
                updated = true;
                log.debug("AdminManager.updateDeviceInfo - IP address updated to {} for user: {}", request.getIpAddress(), username);
            }

            if (request.getLastKnownLatitude() != null && request.getLastKnownLongitude() != null) {
                // Location bilgisi varsa kaydedilebilir
                log.debug("AdminManager.updateDeviceInfo - Location provided: lat={}, lon={}", 
                        request.getLastKnownLatitude(), request.getLastKnownLongitude());
            }

            // DeviceInfo'da bu alanlar yoksa sadece log'layalım
            if (request.getLastLoginDevice() != null && !request.getLastLoginDevice().isBlank()) {
                log.debug("AdminManager.updateDeviceInfo - Device model provided: {}", request.getLastLoginDevice());
                // DeviceInfo model'inde bu alan yoksa metadata'ya eklenebilir
                updated = true;
            }

            if (request.getLastLoginPlatform() != null && !request.getLastLoginPlatform().isBlank()) {
                log.debug("AdminManager.updateDeviceInfo - Platform provided: {}", request.getLastLoginPlatform());
                updated = true;
            }

            if (request.getLastLoginAppVersion() != null && !request.getLastLoginAppVersion().isBlank()) {
                log.debug("AdminManager.updateDeviceInfo - App version provided: {}", request.getLastLoginAppVersion());
                updated = true;
            }

            if (!updated) {
                log.warn("AdminManager.updateDeviceInfo - No device info to update for user: {}", username);
                return new ResponseMessage("Güncellenecek cihaz bilgisi bulunamadı.", false);
            }

            admin.setCurrentDeviceInfo(deviceInfo);
            adminRepository.save(admin);
            log.info("AdminManager.updateDeviceInfo - Device info updated successfully for user: {}", username);

            // Audit log oluştur
            String metadata = String.format("{\"fcmTokenUpdated\":%s,\"ipAddressUpdated\":%s,\"timestamp\":\"%s\"}", 
                    request.getFcmToken() != null, request.getIpAddress() != null, LocalDateTime.now());
            createAuditLog(
                    admin,
                    ActionType.UPDATE_PROFILE,
                    "Admin cihaz bilgilerini güncelledi",
                    deviceInfo,
                    admin.getId(),
                    "ADMIN",
                    null,
                    metadata
            );

            return new ResponseMessage("Cihaz bilgileri başarıyla güncellendi.", true);
        } catch (AdminNotFoundException e) {
            log.error("AdminManager.updateDeviceInfo - Admin not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.updateDeviceInfo - Unexpected error for user: {}", username, e);
            throw e;
        }
    }


    @Override
    public LocationDTO getLocation(String username) throws AdminNotFoundException, NoLocationFoundException {
        log.debug("AdminManager.getLocation - Method called for user: {}", username);
        
        try {
            Admin admin = findByUserNumber(username);
            log.debug("AdminManager.getLocation - Admin found with ID: {}", admin.getId());

            List<Location> locations = admin.getLocationHistory();
            if (locations == null || locations.isEmpty()) {
                log.warn("AdminManager.getLocation - No location found for user: {}", username);
                throw new NoLocationFoundException();
            }

            Location latestLocation = locations.get(0);
            log.debug("AdminManager.getLocation - Latest location found: lat={}, lon={}, recordedAt={}", 
                    latestLocation.getLatitude(), latestLocation.getLongitude(), latestLocation.getRecordedAt());

            LocationDTO locationDTO = LocationDTO.builder()
                    .latitude(latestLocation.getLatitude())
                    .longitude(latestLocation.getLongitude())
                    .recordedAt(latestLocation.getRecordedAt())
                    .userId(admin.getId())
                    .build();

            log.info("AdminManager.getLocation - Location retrieved successfully for user: {}", username);
            return locationDTO;
        } catch (AdminNotFoundException | NoLocationFoundException e) {
            log.error("AdminManager.getLocation - Error for user: {}, Error: {}", username, e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.getLocation - Unexpected error for user: {}", username, e);
            throw e;
        }
    }


    @Override
    public ResponseMessage updateLocation(UpdateLocationRequest request, String username) throws AdminNotFoundException {
        log.debug("AdminManager.updateLocation - Method called for user: {}, Lat: {}, Lon: {}", 
                username, request.getLatitude(), request.getLongitude());
        
        try {
            Admin admin = findByUserNumber(username);
            log.debug("AdminManager.updateLocation - Admin found with ID: {}", admin.getId());

            Location location = new Location();
            location.setLatitude(request.getLatitude());
            location.setLongitude(request.getLongitude());
            location.setRecordedAt(LocalDateTime.now());
            location.setUser(admin);
            
            // Location model'inde speed ve accuracy alanları yoksa sadece log'layalım
            if (request.getSpeed() != null) {
                log.debug("AdminManager.updateLocation - Speed provided: {}", request.getSpeed());
            }
            if (request.getAccuracy() != null) {
                log.debug("AdminManager.updateLocation - Accuracy provided: {}", request.getAccuracy());
            }

            admin.getLocationHistory().add(location);
            adminRepository.save(admin);
            log.info("AdminManager.updateLocation - Location updated successfully for user: {}, Lat: {}, Lon: {}", 
                    username, request.getLatitude(), request.getLongitude());

            // Audit log oluştur
            DeviceInfo deviceInfo = admin.getCurrentDeviceInfo() != null ? admin.getCurrentDeviceInfo() : new DeviceInfo();
            String metadata = String.format("{\"latitude\":%s,\"longitude\":%s,\"speed\":%s,\"accuracy\":%s,\"timestamp\":\"%s\"}", 
                    request.getLatitude(), request.getLongitude(), 
                    request.getSpeed() != null ? request.getSpeed() : "null",
                    request.getAccuracy() != null ? request.getAccuracy() : "null",
                    LocalDateTime.now());
            createAuditLog(
                    admin,
                    ActionType.LOCATION_UPDATED,
                    String.format("Admin lokasyon güncelledi: lat=%s, lon=%s", request.getLatitude(), request.getLongitude()),
                    deviceInfo,
                    admin.getId(),
                    "ADMIN",
                    null,
                    metadata
            );

            return new ResponseMessage("Lokasyon başarıyla güncellendi.", true);
        } catch (AdminNotFoundException e) {
            log.error("AdminManager.updateLocation - Admin not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.updateLocation - Unexpected error for user: {}", username, e);
            throw e;
        }
    }

    @Override
    public DataResponseMessage<Page<LoginHistoryDTO>> getLoginHistory(String username, Pageable pageable) throws AdminNotFoundException {
        log.debug("AdminManager.getLoginHistory - Method called for user: {}, Page: {}, Size: {}", 
                username, pageable.getPageNumber(), pageable.getPageSize());
        
        try {
            Admin admin = findByUserNumber(username);
            log.debug("AdminManager.getLoginHistory - Admin found with ID: {}", admin.getId());

            Page<LoginHistory> historyPage = loginHistoryRepository.findAllByUserOrderByLoginAtDesc(admin, pageable);
            log.debug("AdminManager.getLoginHistory - Found {} login history records", historyPage.getTotalElements());

            Page<LoginHistoryDTO> dtoPage = historyPage.map(login -> LoginHistoryDTO.builder()
                    .ipAddress(login.getIpAddress())
                    .device(login.getDevice())
                    .platform(login.getPlatform())
                    .appVersion(login.getAppVersion())
                    .loginAt(login.getLoginAt())
                    .build()
            );

            log.info("AdminManager.getLoginHistory - Login history retrieved successfully for user: {}, Total: {}", 
                    username, historyPage.getTotalElements());
            return new DataResponseMessage<>("Giriş geçmişi başarıyla getirildi.", true, dtoPage);
        } catch (AdminNotFoundException e) {
            log.error("AdminManager.getLoginHistory - Admin not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.getLoginHistory - Unexpected error for user: {}", username, e);
            throw e;
        }
    }


    @Override
    public DataResponseMessage<AdminDTO> getProfile(String username) throws AdminNotFoundException {
        log.debug("AdminManager.getProfile - Method called for user: {}", username);
        
        try {
            SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                    .orElseThrow(() -> {
                        log.warn("AdminManager.getProfile - SecurityUser not found: {}", username);
                        return new AdminNotFoundException();
                    });
            
            log.debug("AdminManager.getProfile - SecurityUser found with ID: {}", securityUser.getId());

            AdminDTO adminDTO = AdminDTO.builder()
                    .roles(securityUser.getRoles())
                    .phoneNumber(securityUser.getUserNumber())
                    .phoneNumberVerified(securityUser.isPhoneVerified())
                    .email(securityUser.getProfileInfo() != null ? securityUser.getProfileInfo().getEmail() : null)
                    .emailVerified(securityUser.isEmailVerified())
                    .name(securityUser.getProfileInfo() != null ? securityUser.getProfileInfo().getName() : null)
                    .surname(securityUser.getProfileInfo() != null ? securityUser.getProfileInfo().getSurname() : null)
                    .status(securityUser.getStatus())
                    .build();
            
            log.info("AdminManager.getProfile - Profile retrieved successfully for user: {}", username);
            return new DataResponseMessage<>("Kullanıcı bilgileri başarıyla getirildi.", true, adminDTO);
        } catch (AdminNotFoundException e) {
            log.error("AdminManager.getProfile - Admin not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.getProfile - Unexpected error for user: {}", username, e);
            throw e;
        }
    }

    @Override
    public DataResponseMessage<Page<AuditLogDTO>> getAuditLogs(String fromDate, String toDate, String action, String username) {
        log.debug("AdminManager.getAuditLogs - Method called for user: {}, FromDate: {}, ToDate: {}, Action: {}", 
                username, fromDate, toDate, action);
        
        try {
            LocalDateTime from = (fromDate != null && !fromDate.isBlank())
                    ? LocalDate.parse(fromDate).atStartOfDay()
                    : LocalDateTime.of(2000, 1, 1, 0, 0);

            LocalDateTime to = (toDate != null && !toDate.isBlank())
                    ? LocalDate.parse(toDate).atTime(LocalTime.MAX)
                    : LocalDateTime.now();

            log.debug("AdminManager.getAuditLogs - Date range: from={}, to={}", from, to);

            ActionType actionType = null;
            if (action != null && !action.isBlank()) {
                try {
                    actionType = ActionType.valueOf(action.toUpperCase());
                    log.debug("AdminManager.getAuditLogs - Action type parsed: {}", actionType);
                } catch (IllegalArgumentException e) {
                    log.warn("AdminManager.getAuditLogs - Invalid action type: {}", action);
                    return new DataResponseMessage<>("Geçersiz işlem tipi. Lütfen geçerli bir işlem tipi giriniz.", false, Page.empty());
                }
            }

            Admin admin = adminRepository.findByUserNumber(username);
            if (admin == null) {
                log.warn("AdminManager.getAuditLogs - Admin not found: {}", username);
                return new DataResponseMessage<>("Admin bulunamadı.", false, Page.empty());
            }

            log.debug("AdminManager.getAuditLogs - Admin found with ID: {}", admin.getId());

            Pageable pageable = PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "timestamp"));

            Page<AuditLog> logs;

            if (actionType != null) {
                logs = auditLogRepository.findByAdminAndActionAndTimestampBetween(admin, actionType, from, to, pageable);
            } else {
                logs = auditLogRepository.findByAdminAndTimestampBetween(admin, from, to, pageable);
            }

            log.debug("AdminManager.getAuditLogs - Found {} audit logs", logs.getTotalElements());

            Page<AuditLogDTO> dtoPage = logs.map(auditLogConverter::mapToDto);

            log.info("AdminManager.getAuditLogs - Audit logs retrieved successfully for user: {}, Total: {}", 
                    username, logs.getTotalElements());
            return new DataResponseMessage<>("Denetim kayıtları başarıyla getirildi.", true, dtoPage);
        } catch (Exception e) {
            log.error("AdminManager.getAuditLogs - Unexpected error for user: {}", username, e);
            return new DataResponseMessage<>("Denetim kayıtları getirilirken bir hata oluştu.", false, Page.empty());
        }
    }

    @Override
    public DataResponseMessage<List<String>> getMyRoles(String username) throws AdminNotFoundException {
        log.debug("AdminManager.getMyRoles - Method called for user: {}", username);
        
        try {
            Admin admin = findByUserNumber(username);
            log.debug("AdminManager.getMyRoles - Admin found with ID: {}", admin.getId());

            Set<Role> roles = admin.getRoles();
            if (roles == null || roles.isEmpty()) {
                log.warn("AdminManager.getMyRoles - No roles found for user: {}", username);
                return new DataResponseMessage<>("Kullanıcıya atanmış rol bulunamadı.", true, List.of());
            }

            List<String> roleNames = roles.stream()
                    .map(Role::name)
                    .sorted()
                    .collect(Collectors.toList());

            log.info("AdminManager.getMyRoles - Roles retrieved successfully for user: {}, Roles: {}", 
                    username, roleNames);
            return new DataResponseMessage<>("Rolleriniz başarıyla getirildi.", true, roleNames);
        } catch (AdminNotFoundException e) {
            log.error("AdminManager.getMyRoles - Admin not found: {}", username);
            throw e;
        } catch (Exception e) {
            log.error("AdminManager.getMyRoles - Unexpected error for user: {}", username, e);
            throw e;
        }
    }

}
