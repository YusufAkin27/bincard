package akin.city_card.security.manager;

import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.bus.exceptions.DriverNotFoundException;
import akin.city_card.driver.model.Driver;
import akin.city_card.driver.repository.DriverRepository;
import akin.city_card.geoIpService.GeoIpService;
import akin.city_card.location.model.Location;
import akin.city_card.mail.EmailMessage;
import akin.city_card.mail.MailService;
import akin.city_card.notification.model.NotificationPreferences;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.service.FCMService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.entity.*;
import akin.city_card.security.entity.enums.TokenType;
import akin.city_card.security.exception.*;
import akin.city_card.security.filter.SecurityAuditService;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.security.repository.TokenRepository;
import akin.city_card.security.service.BruteForceProtectionService;
import akin.city_card.security.service.JwtService;
import akin.city_card.sms.SmsService;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.user.core.request.UnfreezeAccountRequest;
import akin.city_card.user.exceptions.AccountNotFrozenException;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.User;
import akin.city_card.user.model.UserStatus;
import akin.city_card.user.repository.LoginHistoryRepository;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import akin.city_card.user.service.concretes.UserManager;
import akin.city_card.verification.exceptions.VerificationCodeExpiredException;
import akin.city_card.verification.model.VerificationChannel;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.verification.model.VerificationPurpose;
import akin.city_card.verification.repository.VerificationCodeRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;


@Service
@RequiredArgsConstructor
public class AuthManager implements AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthManager.class);

    private final SecurityUserRepository securityUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final VerificationCodeRepository verificationCodeRepository;
    private final SmsService smsService;
    private final AdminRepository adminRepository;
    private final SuperAdminRepository superAdminRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final DriverRepository driverRepository;
    private final UserManager userManager;
    private final FCMService fcmService;
    private final MailService mailService;
    private final GeoIpService geoIpService;
    private final SecurityAuditService auditService;
    private final BruteForceProtectionService bruteForceService;

    @Override
    @Transactional
    public ResponseMessage logout(String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, TokenNotFoundException {
        try {
            User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

            List<Token> tokens = tokenRepository.findAllBySecurityUserId(user.getId());
            if (tokens == null || tokens.isEmpty()) {
                throw new TokenNotFoundException();
            }

            tokenRepository.deleteAll(tokens);

            // IP adresini mevcut device info'dan al
            String ipAddress = "unknown";
            if (user.getCurrentDeviceInfo() != null && user.getCurrentDeviceInfo().getIpAddress() != null) {
                ipAddress = user.getCurrentDeviceInfo().getIpAddress();
            }

            auditService.logSecurityEvent(SecurityEventType.LOGOUT, username, ipAddress,
                    "User logged out successfully");

            logger.info("User logged out successfully: {}", username);
            return new ResponseMessage("Çıkış başarılı", true);

        } catch (Exception e) {
            logger.error("Logout failed for user: {}", username, e);
            throw e;
        }
    }

    @Override
    @Transactional
    public TokenResponseDTO phoneVerify(LoginPhoneVerifyCodeRequest phoneVerifyCode, HttpServletRequest httpServletRequest)
            throws InvalidVerificationCodeException, VerificationCodeExpiredException,
            UsedVerificationCodeException, CancelledVerificationCodeException {

        String clientIp = extractClientIp(httpServletRequest);

        try {
            VerificationCode verificationCode = verificationCodeRepository
                    .findTopByCodeAndCancelledFalseOrderByCreatedAtDesc(phoneVerifyCode.getCode());

            if (verificationCode == null) {
                auditService.logSuspiciousActivity(clientIp, null, "INVALID_VERIFICATION_CODE",
                        "Invalid verification code attempt: " + phoneVerifyCode.getCode(), httpServletRequest);
                throw new InvalidVerificationCodeException();
            }

            if (verificationCode.isUsed()) {
                auditService.logSuspiciousActivity(clientIp, verificationCode.getUser().getUserNumber(),
                        "USED_VERIFICATION_CODE", "Attempt to use already used verification code", httpServletRequest);
                throw new UsedVerificationCodeException();
            }

            if (verificationCode.isCancelled()) {
                auditService.logSuspiciousActivity(clientIp, verificationCode.getUser().getUserNumber(),
                        "CANCELLED_VERIFICATION_CODE", "Attempt to use cancelled verification code", httpServletRequest);
                throw new CancelledVerificationCodeException();
            }

            if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
                auditService.logSuspiciousActivity(clientIp, verificationCode.getUser().getUserNumber(),
                        "EXPIRED_VERIFICATION_CODE", "Attempt to use expired verification code", httpServletRequest);
                throw new VerificationCodeExpiredException();
            }

            verificationCode.setUsed(true);
            verificationCodeRepository.save(verificationCode);

            SecurityUser user = verificationCode.getUser();

            LoginMetadataDTO metadata = extractClientMetadata(httpServletRequest);

            // Request'ten gelen device bilgilerini metadata'ya ekle
            if (phoneVerifyCode.getDeviceInfo() != null) metadata.setDeviceInfo(phoneVerifyCode.getDeviceInfo());
            if (phoneVerifyCode.getPlatform() != null) metadata.setPlatform(phoneVerifyCode.getPlatform());
            if (phoneVerifyCode.getAppVersion() != null) metadata.setAppVersion(phoneVerifyCode.getAppVersion());
            if (phoneVerifyCode.getDeviceUuid() != null) metadata.setDeviceUuid(phoneVerifyCode.getDeviceUuid());
            if (phoneVerifyCode.getFcmToken() != null) metadata.setFcmToken(phoneVerifyCode.getFcmToken());
            if (phoneVerifyCode.getLatitude() != null) metadata.setLatitude(phoneVerifyCode.getLatitude());
            if (phoneVerifyCode.getLongitude() != null) metadata.setLongitude(phoneVerifyCode.getLongitude());

            // Her kullanıcı türü için tek oturum politikası - mevcut tüm oturumları kapat
            revokePreviousSessions(user, "New login verification completed", httpServletRequest);

            // Cihaz ve IP kontrolü
            if (user instanceof User userEntity) {
                boolean isNewDevice = isNewDevice(userEntity, metadata.getDeviceInfo());
                boolean isNewIp = isNewIp(userEntity, metadata.getIpAddress());

                if (isNewDevice || isNewIp) {
                    auditService.logSecurityEvent(SecurityEventType.NEW_DEVICE_VERIFIED,
                            user.getUsername(), httpServletRequest,
                            String.format("Device/IP verified - New Device: %s, New IP: %s", isNewDevice, isNewIp));

                    logger.info("Device/IP verification completed for user: {} - New Device: {}, New IP: {}",
                            user.getUsername(), isNewDevice, isNewIp);
                }
            }

            applyLoginMetadataToUser(user, metadata);
            securityUserRepository.save(user);

            // Brute force protection - başarılı giriş
            bruteForceService.recordSuccessfulLogin(user.getUsername());

            // Audit log
            auditService.logLoginSuccess(user.getUsername(), httpServletRequest);

            TokenResponseDTO response = generateTokenResponse(user, metadata.getIpAddress(), metadata.getDeviceInfo());

            logger.info("Phone verification successful for user: {} from IP: {}",
                    user.getUsername(), clientIp);
            return response;

        } catch (Exception e) {
            logger.error("Phone verification failed from IP: {}", clientIp, e);
            throw e;
        }
    }

    @Override
    public ResponseMessage adminLogin(LoginRequestDTO loginRequestDTO, HttpServletRequest request)
            throws IncorrectPasswordException, UserRoleNotAssignedException, UserDeletedException,
            AdminNotApprovedException, UserNotActiveException, AdminNotFoundException,
            UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException, AccountFrozenException {

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(loginRequestDTO.getTelephone());
        String clientIp = extractClientIp(request);

        try {
            // Brute force kontrolü
            if (bruteForceService.isAccountLocked(normalizedPhone)) {
                long remainingMinutes = bruteForceService.getRemainingLockTimeMinutes(normalizedPhone);
                auditService.logSecurityEvent(SecurityEventType.ACCOUNT_LOCKED, normalizedPhone, request,
                        "Admin login attempt on locked account");
                throw new AccountFrozenException();
            }

            loginRequestDTO.setTelephone(normalizedPhone);

            Admin admin = adminRepository.findByUserNumber(normalizedPhone);
            if (admin == null) {
                bruteForceService.recordFailedLogin(normalizedPhone, clientIp, request.getHeader("User-Agent"));
                auditService.logLoginFailure(normalizedPhone, request, "Admin not found");
                throw new AdminNotFoundException();
            }

            if (!passwordEncoder.matches(loginRequestDTO.getPassword(), admin.getPassword())) {
                bruteForceService.recordFailedLogin(normalizedPhone, clientIp, request.getHeader("User-Agent"));
                auditService.logLoginFailure(normalizedPhone, request, "Incorrect password");
                throw new IncorrectPasswordException();
            }

            if (admin.getRoles() == null || admin.getRoles().isEmpty()) {
                auditService.logLoginFailure(normalizedPhone, request, "No roles assigned");
                throw new UserRoleNotAssignedException();
            }

            if (admin.isDeleted()) {
                auditService.logLoginFailure(normalizedPhone, request, "Admin account deleted");
                throw new UserDeletedException();
            }

            if (!admin.isSuperAdminApproved()) {
                auditService.logLoginFailure(normalizedPhone, request, "Admin not approved");
                throw new AdminNotApprovedException();
            }

            if (!admin.isEnabled()) {
                auditService.logLoginFailure(normalizedPhone, request, "Admin account disabled");
                throw new UserNotActiveException();
            }

            LoginMetadataDTO metadata = extractClientMetadata(request);
            applyLoginMetadataToUser(admin, metadata);
            adminRepository.save(admin);

            // Admin için HER ZAMAN SMS doğrulaması gönder
            sendLoginVerificationCode(admin.getUserNumber(), metadata.getIpAddress(), metadata.getDeviceInfo(), request);

            auditService.logSecurityEvent(SecurityEventType.ADMIN_LOGIN, normalizedPhone, request,
                    "Admin login verification code sent");

            logger.info("Admin login verification code sent to: {} from IP: {}", normalizedPhone, clientIp);
            return new ResponseMessage("SMS gönderildi, lütfen giriş için kodu giriniz", true);

        } catch (Exception e) {
            logger.error("Admin login failed for: {} from IP: {}", normalizedPhone, clientIp, e);
            throw e;
        }
    }

    @Override
    public ResponseMessage superadminLogin(HttpServletRequest request, LoginRequestDTO loginRequestDTO)
            throws IncorrectPasswordException, UserRoleNotAssignedException, UserNotActiveException,
            UserDeletedException, SuperAdminNotFoundException, UserNotFoundException,
            VerificationCodeStillValidException, VerificationCooldownException, AccountFrozenException {

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(loginRequestDTO.getTelephone());
        String clientIp = extractClientIp(request);

        try {
            // Brute force kontrolü
            if (bruteForceService.isAccountLocked(normalizedPhone)) {
                long remainingMinutes = bruteForceService.getRemainingLockTimeMinutes(normalizedPhone);
                auditService.logSecurityEvent(SecurityEventType.ACCOUNT_LOCKED, normalizedPhone, request,
                        "SuperAdmin login attempt on locked account");
                throw new AccountFrozenException();
            }

            loginRequestDTO.setTelephone(normalizedPhone);

            SuperAdmin superAdmin = superAdminRepository.findByUserNumber(normalizedPhone);
            if (superAdmin == null) {
                bruteForceService.recordFailedLogin(normalizedPhone, clientIp, request.getHeader("User-Agent"));
                auditService.logLoginFailure(normalizedPhone, request, "SuperAdmin not found");
                throw new SuperAdminNotFoundException();
            }

            if (!passwordEncoder.matches(loginRequestDTO.getPassword(), superAdmin.getPassword())) {
                bruteForceService.recordFailedLogin(normalizedPhone, clientIp, request.getHeader("User-Agent"));
                auditService.logLoginFailure(normalizedPhone, request, "Incorrect password");
                throw new IncorrectPasswordException();
            }

            if (superAdmin.getRoles() == null || superAdmin.getRoles().isEmpty()) {
                auditService.logLoginFailure(normalizedPhone, request, "No roles assigned");
                throw new UserRoleNotAssignedException();
            }

            if (superAdmin.isDeleted()) {
                auditService.logLoginFailure(normalizedPhone, request, "SuperAdmin account deleted");
                throw new UserDeletedException();
            }

            if (!superAdmin.isEnabled()) {
                auditService.logLoginFailure(normalizedPhone, request, "SuperAdmin account disabled");
                throw new UserNotActiveException();
            }

            LoginMetadataDTO metadata = extractClientMetadata(request);
            applyLoginMetadataToUser(superAdmin, metadata);
            superAdminRepository.save(superAdmin);

            // SuperAdmin için HER ZAMAN SMS doğrulaması gönder
            sendLoginVerificationCode(superAdmin.getUserNumber(), metadata.getIpAddress(), metadata.getDeviceInfo(), request);

            auditService.logSecurityEvent(SecurityEventType.SUPERADMIN_LOGIN, normalizedPhone, request,
                    "SuperAdmin login verification code sent");

            logger.info("SuperAdmin login verification code sent to: {} from IP: {}", normalizedPhone, clientIp);
            return new ResponseMessage("SMS gönderildi, lütfen giriş için SMS kodunu giriniz", true);

        } catch (Exception e) {
            logger.error("SuperAdmin login failed for: {} from IP: {}", normalizedPhone, clientIp, e);
            throw e;
        }
    }

    @Override
    public TokenDTO refreshLogin(HttpServletRequest request, RefreshLoginRequest refreshRequest)
            throws TokenIsExpiredException, TokenNotFoundException, InvalidRefreshTokenException,
            UserNotFoundException, IncorrectPasswordException {

        if (!jwtService.validateRefreshToken(refreshRequest.getRefreshToken())) {
            throw new InvalidRefreshTokenException();
        }

        String userNumber = jwtService.getRefreshTokenClaims(refreshRequest.getRefreshToken()).getSubject();
        Optional<SecurityUser> optionalSecurityUser = securityUserRepository.findByUserNumber(userNumber);
        if (optionalSecurityUser.isEmpty()) {
            throw new UserNotFoundException();
        }

        SecurityUser user = optionalSecurityUser.get();

        if (!passwordEncoder.matches(refreshRequest.getPassword(), user.getPassword())) {
            auditService.logSecurityEvent(SecurityEventType.LOGIN_FAILED, userNumber, request,
                    "Incorrect password during token refresh");
            throw new IncorrectPasswordException();
        }

        LoginMetadataDTO metadata = extractClientMetadata(request);

        applyLoginMetadataToUser(user, metadata);
        securityUserRepository.save(user);

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);

        String newAccessToken = jwtService.generateAccessToken(
                user,
                metadata.getIpAddress(),
                metadata.getDeviceInfo(),
                accessExpiry
        );

        auditService.logSecurityEvent(SecurityEventType.TOKEN_REFRESH, userNumber, request,
                "Access token refreshed successfully");

        return new TokenDTO(
                newAccessToken,
                issuedAt,
                accessExpiry,
                issuedAt,
                metadata.getIpAddress(),
                metadata.getDeviceInfo(),
                TokenType.ACCESS
        );
    }

    @Override
    public ResponseMessage resendVerifyCode(String telephone, HttpServletRequest request) throws UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException {
        telephone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(telephone);
        SecurityUser user = securityUserRepository.findByUserNumber(telephone).orElseThrow(UserNotFoundException::new);
        sendLoginVerificationCode(telephone, user.getCurrentDeviceInfo().getIpAddress(), null, request);

        auditService.logSecurityEvent(SecurityEventType.VERIFICATION_CODE_RESENT, telephone, request, "Verification code resent");


        return new ResponseMessage("yeni doğrulama kodu gönderildi", true);
    }

    // AuthManager.java içindeki login metodunda düzeltme

    @Override
    @Transactional
    public TokenResponseDTO login(LoginRequestDTO loginRequestDTO, HttpServletRequest request)
            throws NotFoundUserException, UserDeletedException, UserNotActiveException,
            IncorrectPasswordException, UserRoleNotAssignedException, PhoneNotVerifiedException,
            UnrecognizedDeviceException, AdminNotApprovedException, UserNotFoundException,
            VerificationCodeStillValidException, VerificationCooldownException, AccountFrozenException {

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(loginRequestDTO.getTelephone());
        String clientIp = extractClientIp(request);

        try {
            // Brute force kontrolü
            long remainingMinutes = bruteForceService.getRemainingLockTimeMinutes(normalizedPhone);
            if (bruteForceService.isAccountLocked(normalizedPhone)) {
                auditService.logSecurityEvent(SecurityEventType.ACCOUNT_LOCKED, normalizedPhone, request,
                        "Login attempt on locked account");
                throw new AccountFrozenException();
            }

            loginRequestDTO.setTelephone(normalizedPhone);

            // SADECE MEVCUT KULLANICILARI BUL - YENİ OLUŞTURMA!
            SecurityUser securityUser = securityUserRepository.findByUserNumber(normalizedPhone)
                    .orElseThrow(() -> {
                        bruteForceService.recordFailedLogin(normalizedPhone, clientIp, request.getHeader("User-Agent"));
                        auditService.logLoginFailure(normalizedPhone, request, "User not found");
                        return new NotFoundUserException();
                    });

            // Mevcut validasyonlar...
            if (securityUser.getStatus() == UserStatus.FROZEN) {
                auditService.logLoginFailure(normalizedPhone, request, "Account frozen");
                throw new AccountFrozenException();
            }

            if (securityUser.isDeleted()) {
                auditService.logLoginFailure(normalizedPhone, request, "Account deleted");
                throw new UserDeletedException();
            }

            if (!securityUser.getStatus().equals(UserStatus.ACTIVE)) {
                auditService.logLoginFailure(normalizedPhone, request, "Account not active");
                throw new UserNotActiveException();
            }

            if (!passwordEncoder.matches(loginRequestDTO.getPassword(), securityUser.getPassword())) {
                bruteForceService.recordFailedLogin(normalizedPhone, clientIp, request.getHeader("User-Agent"));
                auditService.logLoginFailure(normalizedPhone, request, "Incorrect password");
                throw new IncorrectPasswordException();
            }

            if (securityUser.getRoles() == null || securityUser.getRoles().isEmpty()) {
                auditService.logLoginFailure(normalizedPhone, request, "No roles assigned");
                throw new UserRoleNotAssignedException();
            }

            if (securityUser instanceof User user) {
                if (!user.isEnabled()) {
                    auditService.logLoginFailure(normalizedPhone, request, "User not enabled");
                    throw new UserNotActiveException();
                }

                LoginMetadataDTO metadata = extractClientMetadata(request);

                if (!user.isPhoneVerified()) {
                    sendLoginVerificationCode(user.getUserNumber(), metadata.getIpAddress(), metadata.getDeviceInfo(), request);
                    auditService.logSecurityEvent(SecurityEventType.LOGIN_FAILED, normalizedPhone, request,
                            "Phone not verified - verification code sent");
                    throw new PhoneNotVerifiedException();
                }

                // Cihaz ve IP kontrolü
                boolean isNewDevice = isNewDevice(user, metadata.getDeviceInfo());
                boolean isNewIp = isNewIp(user, metadata.getIpAddress());

                if (isNewDevice || isNewIp) {
                    sendLoginVerificationCode(user.getUserNumber(), metadata.getIpAddress(), metadata.getDeviceInfo(), request);
                    String logMessage = String.format("New device/IP detected - New Device: %s, New IP: %s - SMS verification required",
                            isNewDevice, isNewIp);
                    auditService.logSecurityEvent(SecurityEventType.NEW_DEVICE_LOGIN, normalizedPhone, request, logMessage);
                    logger.info("New device/IP login attempt for user: {} - New Device: {}, New IP: {} - SMS sent",
                            normalizedPhone, isNewDevice, isNewIp);
                    throw new UnrecognizedDeviceException();
                }

                // Tek oturum politikası - mevcut tüm oturumları kapat
                revokePreviousSessions(user, "New login from same device/IP", request);

                TokenResponseDTO tokenResponseDTO = generateTokenResponse(
                        user,
                        metadata.getIpAddress(),
                        metadata.getDeviceInfo()
                );

                // MEVCUT KULLANICIYI GÜNCELLE - YENİ OLUŞTURMA!
                applyLoginMetadataToUser(user, metadata);
                securityUserRepository.save(user); // Bu save işlemi update olacak, insert değil

                // Brute force protection - başarılı giriş
                bruteForceService.recordSuccessfulLogin(normalizedPhone);

                // Audit log
                auditService.logLoginSuccess(normalizedPhone, request);

                logger.info("User login successful: {} from IP: {}", normalizedPhone, clientIp);
                return tokenResponseDTO;
            }

            throw new NotFoundUserException();

        } catch (Exception e) {
            logger.error("Login failed for user: {} from IP: {}", normalizedPhone, clientIp, e);
            throw e;
        }
    }

    /**
     * Mevcut tüm oturumları kapatır (tek oturum politikası)
     */
    private void revokePreviousSessions(SecurityUser user, String reason, HttpServletRequest httpServletRequest) {
        List<Token> activeTokens = tokenRepository.findAllBySecurityUserId(user.getId())
                .stream()
                .filter(Token::isActive)
                .toList();

        if (!activeTokens.isEmpty()) {
            activeTokens.forEach(token -> {
                token.revoke(reason);
                tokenRepository.save(token);
            });
            auditService.logSecurityEvent(
                    SecurityEventType.SESSION_REVOKED,
                    user.getUsername(),
                    httpServletRequest,
                    String.format("Previous sessions revoked - Count: %d, Reason: %s", activeTokens.size(), reason)
            );

            logger.info("Revoked {} active sessions for user: {} - Reason: {}",
                    activeTokens.size(), user.getUsername(), reason);
        }
    }

    /**
     * Yeni cihaz olup olmadığını kontrol eder
     */
    private boolean isNewDevice(SecurityUser user, String currentDeviceInfo) {
        if (currentDeviceInfo == null || currentDeviceInfo.trim().isEmpty()) {
            return true;
        }

        // Son 30 günlük login history'den cihaz kontrolü
        LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);

        List<LoginHistory> recentLogins = user.getLoginHistory().stream()
                .filter(login -> login.getLoginAt().isAfter(thirtyDaysAgo))
                .sorted((h1, h2) -> h2.getLoginAt().compareTo(h1.getLoginAt()))
                .limit(50) // Son 50 girişi kontrol et
                .toList();

        for (LoginHistory login : recentLogins) {
            if (currentDeviceInfo.equals(login.getDevice())) {
                return false; // Tanınan cihaz
            }
        }

        return true; // Yeni cihaz
    }

    /**
     * Yeni IP olup olmadığını kontrol eder
     */
    private boolean isNewIp(SecurityUser user, String currentIp) {
        if (currentIp == null || currentIp.trim().isEmpty()) {
            return true;
        }

        // Son 30 günlük login history'den IP kontrolü
        LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);

        List<LoginHistory> recentLogins = user.getLoginHistory().stream()
                .filter(login -> login.getLoginAt().isAfter(thirtyDaysAgo))
                .sorted((h1, h2) -> h2.getLoginAt().compareTo(h1.getLoginAt()))
                .limit(50) // Son 50 girişi kontrol et
                .toList();

        for (LoginHistory login : recentLogins) {
            if (currentIp.equals(login.getIpAddress())) {
                return false; // Tanınan IP
            }
        }

        return true; // Yeni IP
    }

    @Override
    @Transactional
    public ResponseMessage unfreezeAccount(UnfreezeAccountRequest request, HttpServletRequest httpRequest)
            throws AccountNotFrozenException, UserNotFoundException, IncorrectPasswordException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(request.getTelephone());

        User user = userRepository.findByUserNumber(normalizedPhone)
                .orElseThrow(UserNotFoundException::new);

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            auditService.logSecurityEvent(SecurityEventType.UNFREEZE_FAILED, request.getTelephone(), httpRequest,
                    "Incorrect password during account unfreeze attempt");
            throw new IncorrectPasswordException();
        }

        if (user.getStatus() != UserStatus.FROZEN) {
            throw new AccountNotFrozenException();
        }

        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        userManager.updateDeviceInfoAndCreateAuditLog(
                user,
                httpRequest,
                geoIpService,
                ActionType.UNFREEZE_ACCOUNT,
                "Kullanıcı hesabını yeniden aktif hale getirdi.",
                null,
                null
        );

        auditService.logSecurityEvent(SecurityEventType.ACCOUNT_UNFROZEN, request.getTelephone(), httpRequest,
                "Account successfully unfrozen");

        String notificationTitle = "Hesap Aktifleştirildi";
        String notificationMessage = "Hesabınız başarıyla yeniden aktifleştirildi.";

        NotificationPreferences prefs = user.getNotificationPreferences();

        if (prefs != null) {
            // Push bildirimi
            if (prefs.isPushEnabled()) {
                fcmService.sendNotificationToToken(
                        user,
                        notificationTitle,
                        notificationMessage,
                        NotificationType.SUCCESS,
                        null
                );
            }

            // SMS bildirimi
            if (prefs.isSmsEnabled()) {
                String phone = user.getUserNumber();
                if (phone != null && !phone.isBlank()) {
                 /*
                    SmsRequest smsRequest = new SmsRequest();
                    smsRequest.setTo(phone);
                    smsRequest.setMessage("City Card: " + notificationMessage);
                    smsService.sendSms(smsRequest);
                  */
                }
            }
        }

        // E-posta bildirimi
        if (user.getProfileInfo() != null && user.getProfileInfo().getEmail() != null) {
            EmailMessage message = new EmailMessage();
            message.setToEmail(user.getProfileInfo().getEmail());
            message.setSubject("Hesap Aktifleştirme Bilgilendirmesi");

            String body = """
                        <html>
                            <body style="font-family: Arial, sans-serif; color: #333;">
                                <h2>Sayın %s,</h2>
                                <p>Talebiniz üzerine <strong>%s</strong> tarihinde hesabınız başarıyla yeniden aktifleştirilmiştir.</p>
                                <p>Hizmetlerimizi kullandığınız için teşekkür ederiz. Herhangi bir sorunuz olursa bizimle iletişime geçebilirsiniz.</p>
                                <br>
                                <p>Saygılarımızla,</p>
                                <p><strong>Destek Ekibi</strong></p>
                            </body>
                        </html>
                    """.formatted(
                    user.getProfileInfo().getName() + " " + user.getProfileInfo().getSurname(),
                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm"))
            );

            message.setBody(body);
            message.setHtml(true);
            mailService.queueEmail(message);
        }

        return new ResponseMessage("Hesabınız yeniden aktifleştirildi.", true);
    }


    @Override
    @Transactional
    public TokenResponseDTO driverLogin(HttpServletRequest request, String cardUid)
            throws DriverNotFoundException, IncorrectPasswordException, AccountFrozenException {

        Driver driver=driverRepository.findByCardUid(cardUid).orElseThrow(DriverNotFoundException::new);
        String clientIp = extractClientIp(request);


        if (driver == null) {
            bruteForceService.recordFailedLogin(driver.getUserNumber(), clientIp, request.getHeader("User-Agent"));
            throw new DriverNotFoundException();
        }

        if (driver.getStatus() == UserStatus.FROZEN || !driver.isEnabled()) {
            throw new AccountFrozenException();
        }

        if (driver.isDeleted()) {
            throw new DriverNotFoundException();
        }

        if (!UserStatus.ACTIVE.equals(driver.getStatus())) {
            throw new DriverNotFoundException();
        }

        if (driver.getRoles() == null || driver.getRoles().isEmpty()) {
            throw new DriverNotFoundException();
        }

        if (!driver.isEnabled()) {
            throw new AccountFrozenException();
        }

        LoginMetadataDTO metadata = extractClientMetadata(request);

        TokenResponseDTO tokenResponseDTO = generateTokenResponse(
                driver,
                metadata.getIpAddress(),
                metadata.getDeviceInfo()
        );

        driverRepository.save(driver);

        bruteForceService.recordSuccessfulLogin(driver.getUserNumber());
        auditService.logLoginSuccess(driver.getUserNumber(), request);

        return tokenResponseDTO;
    }

    @Override
    public Set<Role> getRoles(String username) throws UserNotFoundException {
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        return securityUser.getRoles();

    }


    private String extractClientIp(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Originating-IP",
                "CF-Connecting-IP"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }

    public LoginMetadataDTO extractClientMetadata(HttpServletRequest request) {
        String ipAddress = extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String acceptLanguage = request.getHeader("Accept-Language");
        String referer = request.getHeader("Referer");
        String xRealIp = request.getHeader("X-Real-IP");

        return LoginMetadataDTO.builder()
                .ipAddress(ipAddress)
                .deviceInfo(userAgent)
                .platform(request.getHeader("Sec-CH-UA-Platform"))
                .appVersion(request.getHeader("App-Version"))
                .build();
    }


    public void applyLoginMetadataToUser(SecurityUser user, LoginMetadataDTO metadata) {
        LoginHistory history = LoginHistory.builder()
                .loginAt(LocalDateTime.now())
                .ipAddress(metadata.getIpAddress())
                .device(metadata.getDeviceInfo())
                .platform(metadata.getPlatform())
                .appVersion(metadata.getAppVersion())
                .user(user)
                .build();

        if (metadata.getLatitude() != null && metadata.getLongitude() != null) {
            Location location = Location.builder()
                    .latitude(metadata.getLatitude())
                    .longitude(metadata.getLongitude())
                    .recordedAt(LocalDateTime.now())
                    .user(user)
                    .build();

            history.setLocation(location);
            user.setLastKnownLocation(location);

            if (user.getLocationHistory() == null) {
                user.setLocationHistory(new ArrayList<>());
            }
            user.getLocationHistory().add(location);
        }

        if (user.getCurrentDeviceInfo() == null) {
            user.setCurrentDeviceInfo(new DeviceInfo());
        }

        user.getCurrentDeviceInfo().setIpAddress(metadata.getIpAddress());
        user.getCurrentDeviceInfo().setFcmToken(metadata.getFcmToken());

        user.getCurrentDeviceInfo().setDeviceType(metadata.getDeviceInfo());
        user.getCurrentDeviceInfo().setUserAgent(metadata.getDeviceInfo());

        user.setLastLocationUpdatedAt(LocalDateTime.now());

        if (user.getLoginHistory() == null) {
            user.setLoginHistory(new ArrayList<>());
        }
        user.getLoginHistory().add(history);
    }

    @Transactional
    public TokenResponseDTO generateTokenResponse(SecurityUser user, String ipAddress, String deviceInfo) {
        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);
        LocalDateTime refreshExpiry = issuedAt.plusDays(7);

        try {
            // 1. Önce mevcut tüm token'ları sil
            tokenRepository.deleteAllTokensByUser(user);
            tokenRepository.flush(); // Silme işleminin hemen commit edilmesini sağla

            logger.info("Deleted all existing tokens for user: {}", user.getUsername());

            // 2. Yeni token değerlerini oluştur
            String accessTokenValue = jwtService.generateAccessToken(user, ipAddress, deviceInfo, accessExpiry);
            String refreshTokenValue = jwtService.generateRefreshToken(user, ipAddress, deviceInfo, refreshExpiry);

            // 3. Token DTO'larını oluştur
            TokenDTO accessToken = new TokenDTO(
                    accessTokenValue,
                    issuedAt,
                    accessExpiry,
                    issuedAt,
                    ipAddress,
                    deviceInfo,
                    TokenType.ACCESS
            );

            TokenDTO refreshToken = new TokenDTO(
                    refreshTokenValue,
                    issuedAt,
                    refreshExpiry,
                    issuedAt,
                    ipAddress,
                    deviceInfo,
                    TokenType.REFRESH
            );

            logger.info("Generated new tokens for user: {} from IP: {}", user.getUsername(), ipAddress);

            return new TokenResponseDTO(accessToken, refreshToken);

        } catch (Exception e) {
            logger.error("Error generating token response for user: {} from IP: {}", user.getUsername(), ipAddress, e);

            try {
                tokenRepository.deleteAllTokensByUser(user);
                tokenRepository.flush();

                // Tekrar token oluştur
                String accessTokenValue = jwtService.generateAccessToken(user, ipAddress, deviceInfo, accessExpiry);
                String refreshTokenValue = jwtService.generateRefreshToken(user, ipAddress, deviceInfo, refreshExpiry);

                TokenDTO accessToken = new TokenDTO(
                        accessTokenValue,
                        issuedAt,
                        accessExpiry,
                        issuedAt,
                        ipAddress,
                        deviceInfo,
                        TokenType.ACCESS
                );

                TokenDTO refreshToken = new TokenDTO(
                        refreshTokenValue,
                        issuedAt,
                        refreshExpiry,
                        issuedAt,
                        ipAddress,
                        deviceInfo,
                        TokenType.REFRESH
                );

                logger.info("Successfully generated tokens on retry for user: {}", user.getUsername());
                return new TokenResponseDTO(accessToken, refreshToken);

            } catch (Exception retryException) {
                logger.error("Failed to generate tokens even after retry for user: {}", user.getUsername(), retryException);
                throw new RuntimeException("Token generation failed after retry", retryException);
            }
        }
    }


    private void sendLoginVerificationCode(String telephone, String ipAddress, String userAgent, HttpServletRequest request)
            throws UserNotFoundException, VerificationCooldownException, VerificationCodeStillValidException {

        SecurityUser user = securityUserRepository.findByUserNumber(telephone)
                .orElseThrow(UserNotFoundException::new);

        LocalDateTime now = LocalDateTime.now();

        VerificationCode lastCode = verificationCodeRepository.findAll().stream()
                .filter(vc -> vc.getUser().getId().equals(user.getId())
                        && vc.getPurpose() == VerificationPurpose.LOGIN)
                .max(Comparator.comparing(VerificationCode::getCreatedAt))
                .orElse(null);

        if (lastCode != null && !lastCode.isUsed() && !lastCode.isCancelled() && lastCode.getExpiresAt().isAfter(now)) {
            Duration timeSinceSent = Duration.between(lastCode.getCreatedAt(), now);
            long secondsSinceSent = timeSinceSent.toSeconds();
            long cooldownSeconds = 180; // 3 dakika
            long remainingSeconds = cooldownSeconds - secondsSinceSent;

            if (remainingSeconds > 0) {
                auditService.logSuspiciousActivity(ipAddress, telephone, "VERIFICATION_COOLDOWN",
                        String.format("Verification code requested too soon - %d seconds remaining", remainingSeconds), null);
                throw new VerificationCooldownException(remainingSeconds);
            }

            auditService.logSuspiciousActivity(ipAddress, telephone, "VERIFICATION_CODE_STILL_VALID",
                    "Attempt to request new verification code while previous is still valid", null);
            throw new VerificationCodeStillValidException();
        }

        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.LOGIN);

        String code = randomSixDigit();

        VerificationCode verificationCode = VerificationCode.builder()
                .code(code)
                .user(user)
                .createdAt(now)
                .expiresAt(now.plusMinutes(3))
                .channel(VerificationChannel.SMS)
                .used(false)
                .cancelled(false)
                .purpose(VerificationPurpose.LOGIN)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        verificationCodeRepository.save(verificationCode);

        auditService.logSecurityEvent(
                SecurityEventType.VERIFICATION_CODE_SENT,
                telephone,
                request, // gerçek HttpServletRequest nesnesi
                String.format(
                        "Login verification code sent via SMS - Code expires at: %s",
                        verificationCode.getExpiresAt().format(DateTimeFormatter.ofPattern("HH:mm:ss"))
                )
        );


/*
        SmsRequest smsRequest = new SmsRequest();
        smsRequest.setMessage(verificationCode.getCode());
        smsRequest.setTo(telephone);
        smsService.sendSms(smsRequest);
*/

        System.out.println("📩 Yeni gönderilen kod: " + code);
        logger.info("Verification code sent to: {} from IP: {}", telephone, ipAddress);
    }

    public String randomSixDigit() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000));
    }

    @Override
    public TokenDTO updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO, HttpServletRequest request)
            throws UserNotFoundException, InvalidRefreshTokenException, TokenIsExpiredException, TokenNotFoundException {

        if (!jwtService.validateRefreshToken(updateAccessTokenRequestDTO.getRefreshToken())) {
            throw new InvalidRefreshTokenException();
        }

        String userNumber = jwtService.getRefreshTokenClaims(updateAccessTokenRequestDTO.getRefreshToken()).getSubject();

        SecurityUser user = securityUserRepository.findByUserNumber(userNumber)
                .orElseThrow(UserNotFoundException::new);

        LoginMetadataDTO metadata = extractClientMetadata(request);

        applyLoginMetadataToUser(user, metadata);
        securityUserRepository.save(user);

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);

        String newAccessToken = jwtService.generateAccessToken(
                user,
                metadata.getIpAddress(),
                metadata.getDeviceInfo(),
                accessExpiry
        );

        auditService.logSecurityEvent(SecurityEventType.TOKEN_REFRESH, userNumber, request,
                "Access token updated successfully");

        return new TokenDTO(
                newAccessToken,
                issuedAt,
                accessExpiry,
                issuedAt,
                metadata.getIpAddress(),
                metadata.getDeviceInfo(),
                TokenType.ACCESS
        );
    }
}