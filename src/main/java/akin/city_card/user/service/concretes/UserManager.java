package akin.city_card.user.service.concretes;

import akin.city_card.admin.core.converter.AuditLogConverter;
import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.model.ActionType;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.buscard.core.converter.BusCardConverter;
import akin.city_card.buscard.core.request.FavoriteCardRequest;
import akin.city_card.buscard.core.response.FavoriteBusCardDTO;
import akin.city_card.buscard.exceptions.BusCardNotFoundException;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.UserFavoriteCard;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.contract.service.abstacts.ContractService;
import akin.city_card.geoIpService.GeoIpService;
import akin.city_card.geoIpService.GeoLocationData;
import akin.city_card.location.model.Location;
import akin.city_card.mail.EmailMessage;
import akin.city_card.mail.MailService;
import akin.city_card.notification.core.request.NotificationPreferencesDTO;
import akin.city_card.notification.model.Notification;
import akin.city_card.notification.model.NotificationPreferences;
import akin.city_card.notification.model.NotificationType;
import akin.city_card.notification.repository.NotificationRepository;
import akin.city_card.notification.service.FCMService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.ProfileInfo;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.*;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.security.repository.TokenRepository;
import akin.city_card.sms.SmsRequest;
import akin.city_card.sms.SmsService;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.core.response.Views;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.model.PasswordResetToken;
import akin.city_card.user.model.SearchHistory;
import akin.city_card.user.model.User;
import akin.city_card.user.model.UserStatus;
import akin.city_card.user.repository.LoginHistoryRepository;
import akin.city_card.user.repository.PasswordResetTokenRepository;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.verification.exceptions.*;
import akin.city_card.verification.model.VerificationChannel;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.verification.model.VerificationPurpose;
import akin.city_card.verification.repository.VerificationCodeRepository;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserManager implements UserService {
    private final UserRepository userRepository;
    private final UserConverter userConverter;
    private final SmsService smsService;
    private final MailService mailService;
    private final MediaUploadService mediaUploadService;
    private final VerificationCodeRepository verificationCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final SecurityUserRepository securityUserRepository;
    private final BusCardConverter busCardConverter;
    private final BusCardRepository busCardRepository;
    private final AuditLogRepository auditLogRepository;
    private final NotificationRepository notificationRepository;
    private final AuditLogConverter auditLogConverter;
    private final FCMService fcmService;
    private final GeoIpService geoIpService;
    private final ContractService contractService;
    private final LoginHistoryRepository loginHistoryRepository;
    private final TokenRepository tokenRepository;


    @Override
    @Transactional
    public ResponseMessage create(CreateUserRequest request, HttpServletRequest httpServletRequest) throws VerificationCodeStillValidException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(request.getTelephone());
        request.setTelephone(normalizedPhone);

        Optional<SecurityUser> existingUserOpt = securityUserRepository.findByUserNumber(normalizedPhone);

        if (existingUserOpt.isPresent() && !existingUserOpt.get().isEnabled()) {
            SecurityUser existingUser = existingUserOpt.get();

            VerificationCode lastCode = verificationCodeRepository.findAll().stream()
                    .filter(vc -> vc.getUser().getId().equals(existingUser.getId()) &&
                            vc.getPurpose() == VerificationPurpose.REGISTER)
                    .max(Comparator.comparing(VerificationCode::getCreatedAt))
                    .orElse(null);

            if (lastCode != null && !lastCode.isUsed() && !lastCode.isCancelled()
                    && lastCode.getExpiresAt().isAfter(LocalDateTime.now())) {
                throw new VerificationCodeStillValidException();
            }

            verificationCodeRepository.cancelAllActiveCodes(existingUser.getId(), VerificationPurpose.REGISTER);
            sendVerificationCode(existingUser, VerificationPurpose.REGISTER);

            return new ResponseMessage("Telefon numarası daha önce kayıt olmuş ancak aktif edilmemiş. Yeni doğrulama kodu gönderildi.", true);
        }

        User user = userConverter.convertUserToCreateUser(request);
        user.setStatus(UserStatus.UNVERIFIED);

        userRepository.save(user);

        // IP ve User-Agent bilgilerini al
        String ipAddress = extractClientIp(httpServletRequest);
        String userAgent = httpServletRequest.getHeader("User-Agent");

        // Zorunlu sözleşmeleri otomatik olarak kabul et
        try {
            contractService.autoAcceptMandatoryContracts(user, ipAddress, userAgent);
            log.info("Zorunlu sözleşmeler otomatik kabul edildi - Kullanıcı: {}", normalizedPhone);
        } catch (Exception e) {
            log.error("Zorunlu sözleşmeler otomatik kabul edilirken hata - Kullanıcı: {}", normalizedPhone, e);
            // Sözleşme kabul hatası kullanıcı kaydını engellemez, sadece log'lanır
        }

        sendVerificationCode(user, VerificationPurpose.REGISTER);

        createNotification(
                user,
                "Kayıt Başarılı",
                "Kayıt işleminiz başarıyla tamamlandı. SMS ile gelen doğrulama kodunu kullanarak hesabınızı aktifleştirebilirsiniz.",
                NotificationType.INFO,
                null
        );

        updateDeviceInfoAndCreateAuditLog(
                user,
                httpServletRequest,
                geoIpService,
                ActionType.USER_REGISTER,
                "Yeni kullanıcı kaydı yapıldı: " + user.getProfileInfo().getName() + " " + user.getProfileInfo().getSurname(),
                null,
                "Telefon: " + normalizedPhone
        );

        return new ResponseMessage("Kullanıcı başarıyla oluşturuldu. Doğrulama kodu SMS olarak gönderildi.", true);
    }


    public DeviceInfo buildDeviceInfoFromRequest(HttpServletRequest httpRequest, GeoIpService geoIpService) {
        String ipAddress = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        String deviceType = "Unknown";
        if (userAgent != null) {
            String uaLower = userAgent.toLowerCase();
            if (uaLower.contains("mobile")) deviceType = "Mobile";
            else if (uaLower.contains("tablet")) deviceType = "Tablet";
            else deviceType = "Desktop";
        }

        GeoLocationData geoData = geoIpService.getGeoData(ipAddress);
        return DeviceInfo.builder()
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceType(deviceType)
                .city(Optional.ofNullable(geoData).map(GeoLocationData::getCity).orElse(null))
                .region(Optional.ofNullable(geoData).map(GeoLocationData::getRegion).orElse(null))
                .timezone(Optional.ofNullable(geoData).map(GeoLocationData::getTimezone).orElse(null))
                .org(Optional.ofNullable(geoData).map(GeoLocationData::getOrg).orElse(null))
                .build();
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


    @Transactional
    public void sendVerificationCode(SecurityUser user, VerificationPurpose purpose) {
        String code = randomSixDigit();
        LocalDateTime now = LocalDateTime.now();

        VerificationCode verificationCode = VerificationCode.builder()
                .code(code)
                .user(user)
                .createdAt(now)
                .expiresAt(now.plusMinutes(3))
                .channel(VerificationChannel.SMS)
                .used(false)
                .cancelled(false)
                .purpose(purpose)
                .build();

        verificationCodeRepository.save(verificationCode);
/*
         SmsRequest smsRequest = new SmsRequest();
         smsRequest.setTo(user.getUserNumber());
         smsRequest.setMessage("City Card Sistemine Hoş Geldiniz. Doğrulama kodunuz: " + code + ". Kod 3 dakika boyunca geçerlidir. Güvenliğiniz için bu kodu kimseyle paylaşmayınız.");
         smsService.sendSms(smsRequest);


 */
        System.out.println("Yeni kayıt doğrulama kodu: " + code);
    }

    public void updateDeviceInfoAndCreateAuditLog(
            SecurityUser user,
            HttpServletRequest httpRequest,
            GeoIpService geoIpService,
            ActionType action,
            String description,
            BigDecimal amount,
            String metadata
    ) {
        DeviceInfo deviceInfo = buildDeviceInfoFromRequest(httpRequest, geoIpService);

        String referer = httpRequest.getHeader("Referer");
        String fullMetadata = (metadata == null ? "" : metadata + ", ") + (referer != null ? "Referer: " + referer : "");

        user.setCurrentDeviceInfo(deviceInfo);

        createAuditLog(
                user,
                action,
                description,
                deviceInfo,
                user.getId(),
                user.getRoles().toString(),
                amount,
                fullMetadata,
                referer

        );
    }


    @Override
    @Transactional
    public ResponseMessage verifyPhone(VerificationCodeRequest request, HttpServletRequest httpServletRequest)
            throws UserNotFoundException, VerificationCodeNotFoundException,
            UsedVerificationCodeException, CancelledVerificationCodeException,
            VerificationCodeExpiredException {

        VerificationCode verificationCode = verificationCodeRepository
                .findTopByCodeOrderByCreatedAtDesc(request.getCode());

        if (verificationCode == null) {
            throw new VerificationCodeNotFoundException();
        }

        if (verificationCode.isUsed()) {
            throw new UsedVerificationCodeException();
        }

        if (verificationCode.isCancelled()) {
            throw new CancelledVerificationCodeException();
        }

        if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            verificationCode.setCancelled(true);
            verificationCodeRepository.save(verificationCode);
            throw new VerificationCodeExpiredException();
        }

        SecurityUser securityUser = verificationCode.getUser();
        if (!(securityUser instanceof User user)) {
            throw new UserNotFoundException();
        }


        user.setPhoneVerified(true);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        verificationCode.setUsed(true);
        verificationCode.setVerifiedAt(LocalDateTime.now());
        verificationCodeRepository.save(verificationCode);

        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.REGISTER);

        updateDeviceInfoAndCreateAuditLog(
                user,
                httpServletRequest,
                geoIpService,
                ActionType.USER_PHONE_VERIFIED,
                "Kullanıcı telefon doğrulamasını tamamladı.",
                null,
                "IP: " + extractClientIp(httpServletRequest)
        );

        fcmService.sendNotificationToToken(
                user,
                "Hoşgeldiniz!",
                "Telefon numaranız başarıyla doğrulandı ve hesabınız aktif edildi.",
                NotificationType.SUCCESS,
                null
        );

        return new ResponseMessage("Telefon numarası başarıyla doğrulandı. Hesabınız aktif hale getirildi.", true);
    }

    public void createAuditLog(SecurityUser user,
                               ActionType action,
                               String description,
                               DeviceInfo deviceInfo,
                               Long targetEntityId,
                               String targetEntityType,
                               BigDecimal amount,
                               String metadata,
                               String referer) {

        AuditLog auditLog = new AuditLog();
        auditLog.setUser(user);
        auditLog.setAction(action);
        auditLog.setDescription(description);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setDeviceInfo(deviceInfo);
        auditLog.setTargetEntityId(targetEntityId);
        auditLog.setTargetEntityType(targetEntityType);
        auditLog.setAmount(amount);
        auditLog.setMetadata(metadata);
        auditLog.setReferer(referer);

        auditLogRepository.save(auditLog);
    }


    public void createNotification(User user,
                                   String title,
                                   String message,
                                   NotificationType type,
                                   String targetUrl) {

        Notification notification = Notification.builder()
                .user(user)
                .title(title)
                .message(message)
                .type(type)
                .targetUrl(targetUrl)
                .build();

        notificationRepository.save(notification);
    }


    @Override
    public CacheUserDTO getProfile(String username, HttpServletRequest httpServletRequest) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        updateDeviceInfoAndCreateAuditLog(
                user,
                httpServletRequest,
                geoIpService,
                ActionType.USER_PROFILE_VIEWED,
                "Kullanıcı profil görüntülendi.",
                null,
                null
        );

        userRepository.save(user);

        return userConverter.toCacheUserDTO(user);
    }


    @Override
    @Transactional
    public ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest, HttpServletRequest httpServletRequest) throws UserNotFoundException, EmailAlreadyExistsException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        boolean isUpdated = false;

        if (updateProfileRequest.getName() != null && !updateProfileRequest.getName().isEmpty() &&
                !updateProfileRequest.getName().equals(user.getProfileInfo().getName())) {
            user.getProfileInfo().setName(updateProfileRequest.getName());
            isUpdated = true;
        }

        if (updateProfileRequest.getSurname() != null && !updateProfileRequest.getSurname().isEmpty() &&
                !updateProfileRequest.getSurname().equals(user.getProfileInfo().getSurname())) {
            user.getProfileInfo().setSurname(updateProfileRequest.getSurname());
            isUpdated = true;
        }
        if (updateProfileRequest.getEmail() != null && !updateProfileRequest.getEmail().isBlank()) {
            String newEmail = updateProfileRequest.getEmail().trim().toLowerCase();


            boolean emailAlreadyInUse = securityUserRepository.existsByProfileInfoEmail(newEmail);
            if (emailAlreadyInUse) {
                throw new EmailAlreadyExistsException();
            }

            if (user.getProfileInfo() == null) {
                user.setProfileInfo(new ProfileInfo());
            }

            String currentEmail = user.getProfileInfo().getEmail();

            if (!newEmail.equalsIgnoreCase(currentEmail)) {
                user.getProfileInfo().setEmail(newEmail);
                user.setEmailVerified(false);

                verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.EMAIL_VERIFICATION);

                String token = UUID.randomUUID().toString();
                VerificationCode verificationCode = new VerificationCode();
                verificationCode.setCode(token);
                verificationCode.setCreatedAt(LocalDateTime.now());
                verificationCode.setExpiresAt(LocalDateTime.now().plusMinutes(15));
                verificationCode.setUsed(false);
                verificationCode.setCancelled(false);
                verificationCode.setUser(user);
                verificationCode.setPurpose(VerificationPurpose.EMAIL_VERIFICATION);
                verificationCode.setChannel(VerificationChannel.EMAIL);
                verificationCodeRepository.save(verificationCode);

                String verificationLink = "http://localhost:8080/v1/api/user/email-verify/" + token
                        + "?email=" + URLEncoder.encode(newEmail, StandardCharsets.UTF_8);
                System.out.println(verificationLink);
                String fullName = (user.getProfileInfo().getName() != null ? user.getProfileInfo().getName() : "") + " "
                        + (user.getProfileInfo().getSurname() != null ? user.getProfileInfo().getSurname() : "");
                String htmlContent = """
                        <html>
                          <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 30px;">
                            <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px;">
                              <h2 style="color: #333;">E-posta Adresinizi Doğrulayın</h2>
                              <p>Merhaba <strong>%s</strong>,</p>
                              <p>Yeni e-posta adresinizi doğrulamak için aşağıdaki butona tıklayın:</p>
                              <div style="text-align: center; margin: 30px 0;">
                                <a href="%s" style="background-color: #4CAF50; color: white; padding: 14px 25px; text-decoration: none; border-radius: 5px;">E-Postamı Doğrula</a>
                              </div>
                              <p>Bu bağlantı <strong>15 dakika</strong> boyunca geçerlidir.</p>
                              <hr style="border: none; border-top: 1px solid #eee;">
                              <p style="font-size: 12px; color: #888;">Bu mesajı siz istemediyseniz lütfen dikkate almayın.</p>
                            </div>
                          </body>
                        </html>
                        """.formatted(fullName.trim(), verificationLink);

                EmailMessage emailMessage = new EmailMessage();
                emailMessage.setToEmail(newEmail);
                emailMessage.setSubject("E-Posta Doğrulama");
                emailMessage.setBody(htmlContent);
                emailMessage.setHtml(true);
                mailService.queueEmail(emailMessage);

                System.out.println("Email verification link: " + verificationLink);

                isUpdated = true;
            }


        }


        if (isUpdated) {
            if (user.getCurrentDeviceInfo() == null) {
                user.setCurrentDeviceInfo(new DeviceInfo());
            }

            userRepository.save(user);

            fcmService.sendNotificationToToken(
                    user,
                    "Profil Güncelleme",
                    "Profil bilgileriniz başarıyla güncellendi.",
                    NotificationType.SUCCESS,
                    null
            );
            updateDeviceInfoAndCreateAuditLog(
                    user,
                    httpServletRequest,
                    geoIpService,
                    ActionType.USER_PROFILE_UPDATED,
                    "Kullanıcı profil bilgilerini güncelledi.",
                    null,
                    null
            );


            return new ResponseMessage("Profil başarıyla güncellendi.", true);
        }

        return new ResponseMessage("Herhangi bir değişiklik yapılmadı.", false);
    }


    @Override
    @Transactional
    public ResponseMessage updateProfilePhoto(String username, MultipartFile file, HttpServletRequest httpServletRequest)
            throws PhotoSizeLargerException, IOException, UserNotFoundException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        try {
            String imageUrl = mediaUploadService.uploadAndOptimizeMedia(file);
            user.getProfileInfo().setProfilePicture(imageUrl);

            userRepository.save(user);

            updateDeviceInfoAndCreateAuditLog(
                    user,
                    httpServletRequest,
                    geoIpService,
                    ActionType.USER_PROFILE_PHOTO_UPDATED,
                    "Kullanıcı profil fotoğrafını güncelledi.",
                    null,
                    null
            );


            Notification notification = Notification.builder()
                    .user(user)
                    .title("Profil Fotoğrafı Güncellendi")
                    .message("Profil fotoğrafınız başarıyla güncellendi.")
                    .type(NotificationType.SUCCESS)
                    .targetUrl(null)
                    .build();
            notificationRepository.save(notification);

            return new ResponseMessage("Profil fotoğrafı başarıyla güncellendi.", true);

        } catch (OnlyPhotosAndVideosException | VideoSizeLargerException | FileFormatCouldNotException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    @Transactional
    public ResponseMessage sendPasswordResetCode(String phone, HttpServletRequest httpServletRequest) throws UserNotFoundException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(phone);
        User user = userRepository.findByUserNumber(normalizedPhone)
                .orElseThrow(UserNotFoundException::new);

        String code = randomSixDigit();
        System.out.println("Doğrulama kodu: " + code);

        VerificationCode verificationCode = VerificationCode.builder()
                .user(user)
                .code(code)
                .channel(VerificationChannel.SMS) // default channel, gerçek gönderimde değişebilir
                .purpose(VerificationPurpose.RESET_PASSWORD)
                .expiresAt(LocalDateTime.now().plusMinutes(3))
                .build();

        verificationCodeRepository.save(verificationCode);

        updateDeviceInfoAndCreateAuditLog(
                user,
                httpServletRequest,
                geoIpService,
                ActionType.PASSWORD_RESET_CODE_SENT,
                "Şifre sıfırlama doğrulama kodu gönderildi.",
                null,
                "Kod: " + code
        );

        NotificationPreferences prefs = user.getNotificationPreferences();

        // Bildirim mesajı
        String message = String.format(
                "City Card Güvenlik Kodu: %s\nLütfen bu kodu 3 dakika içinde kullanarak işleminizi tamamlayınız.\nKodunuzu kimseyle paylaşmayınız.",
                code
        );

        boolean notificationSent = false;

        if (prefs != null) {
            if (prefs.isPushEnabled() && user.getCurrentDeviceInfo() != null && user.getCurrentDeviceInfo().getFcmToken() != null) {
                fcmService.sendNotificationToToken(
                        user,
                        "Şifre Sıfırlama Kodu",
                        message,
                        NotificationType.INFO,
                        null
                );
                notificationSent = true;
                verificationCode.setChannel(VerificationChannel.PUSH);
            }

            if (!notificationSent && prefs.isSmsEnabled()) {
                SmsRequest smsRequest = new SmsRequest();
                smsRequest.setTo(normalizedPhone);
                smsRequest.setMessage(message);
                smsService.sendSms(smsRequest);
                notificationSent = true;
                verificationCode.setChannel(VerificationChannel.SMS);
            }

            if (!notificationSent && prefs.isEmailEnabled()) {
                if (user.getProfileInfo() != null
                        && user.getProfileInfo().getEmail() != null
                        && user.isEmailVerified()) {

                    EmailMessage emailMessage = new EmailMessage();
                    emailMessage.setToEmail(user.getProfileInfo().getEmail());
                    emailMessage.setSubject("City Card - Şifre Sıfırlama Kodu");
                    emailMessage.setBody("<p>" + message.replace("\n", "<br>") + "</p>");
                    emailMessage.setHtml(true);
                    mailService.queueEmail(emailMessage);
                    notificationSent = true;
                    verificationCode.setChannel(VerificationChannel.EMAIL);
                }
            }
        }

        if (!notificationSent) {
            /*
            SmsRequest smsRequest = new SmsRequest();
            smsRequest.setTo(normalizedPhone);
            smsRequest.setMessage(message);
            smsService.sendSms(smsRequest);
            verificationCode.setChannel(VerificationChannel.SMS);

             */
        }

        verificationCodeRepository.save(verificationCode);

        return new ResponseMessage("Doğrulama kodu gönderildi.", true);
    }


    @Override
    @Transactional
    public ResponseMessage resetPassword(PasswordResetRequest request, HttpServletRequest httpServletRequest)
            throws PasswordResetTokenNotFoundException,
            PasswordResetTokenExpiredException,
            PasswordResetTokenIsUsedException,
            SamePasswordException {

        PasswordResetToken passwordResetToken = passwordResetTokenRepository
                .findByToken(request.getResetToken())
                .orElseThrow(PasswordResetTokenNotFoundException::new);

        if (passwordResetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new PasswordResetTokenExpiredException();
        }

        if (passwordResetToken.isUsed()) {
            throw new PasswordResetTokenIsUsedException();
        }

        SecurityUser user = passwordResetToken.getUser();
        String newPassword = request.getNewPassword();

        if (newPassword.length() < 6) {
            throw new SamePasswordException();
        }

        if (passwordEncoder.matches(newPassword, user.getPassword())) {
            throw new SamePasswordException();
        }

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        securityUserRepository.save(user);

        passwordResetToken.setUsed(true);
        passwordResetTokenRepository.save(passwordResetToken);

        String ipAddress = extractClientIp(httpServletRequest);
        String userAgent = httpServletRequest.getHeader("User-Agent");

        updateDeviceInfoAndCreateAuditLog(
                user,
                httpServletRequest,
                geoIpService,
                ActionType.USER_PASSWORD_RESET,
                "Kullanıcı şifresini sıfırladı.",
                null,
                null
        );


        if (user instanceof User appUser) {
            String title = "Şifre Sıfırlama";
            String message = "Şifreniz başarıyla sıfırlandı.";
            NotificationType type = NotificationType.SUCCESS;

            fcmService.sendNotificationToToken(appUser, title, message, type, null);

            if (appUser.getNotificationPreferences() != null && appUser.getNotificationPreferences().isSmsEnabled()) {
                String phone = appUser.getUserNumber();
                SmsRequest smsRequest = new SmsRequest();
                smsRequest.setTo(phone);
                smsRequest.setMessage("City Card: Şifreniz başarıyla sıfırlandı.");
                smsService.sendSms(smsRequest);
            }

        }

        return new ResponseMessage("Şifreniz başarıyla sıfırlandı.", true);
    }


    @Override
    @Transactional
    public ResponseMessage changePassword(String username, ChangePasswordRequest request, HttpServletRequest httpServletRequest)
            throws UserIsDeletedException, UserNotActiveException, UserNotFoundException, InvalidNewPasswordException, IncorrectCurrentPasswordException, SamePasswordException {

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        if (!user.isEnabled()) {
            throw new UserNotActiveException();
        }

        if (user.isDeleted()) {
            throw new UserIsDeletedException();
        }

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IncorrectCurrentPasswordException();
        }

        if (request.getNewPassword() == null || request.getNewPassword().length() < 6) {
            throw new InvalidNewPasswordException();
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new SamePasswordException();
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);


        String title = "Şifre Güncelleme";
        String message = "Şifreniz başarıyla güncellendi.";
        NotificationType type = NotificationType.SUCCESS;

        fcmService.sendNotificationToToken(user, title, message, type, null);

        return new ResponseMessage("Şifre başarıyla güncellendi.", true);
    }


    @Override
    public ResponseMessage resendPhoneVerificationCode(ResendPhoneVerificationRequest resendPhoneVerification) throws UserNotFoundException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(resendPhoneVerification.getTelephone());
        resendPhoneVerification.setTelephone(normalizedPhone);

        User user = userRepository.findByUserNumber(resendPhoneVerification.getTelephone()).orElseThrow(UserNotFoundException::new);

        String code = randomSixDigit();

/*
        SmsRequest smsRequest = new SmsRequest();
        smsRequest.setTo(resendPhoneVerification.getTelephone());
        smsRequest.setMessage("City Card - Doğrulama kodunuz: " + code +
                ". Kod 3 dakika boyunca geçerlidir.");
        smsService.sendSms(smsRequest);


 */

        VerificationCode verificationCode = new VerificationCode();
        verificationCode.setCode(code);
        verificationCode.setCreatedAt(LocalDateTime.now());
        verificationCode.setUser(user);
        verificationCode.setChannel(VerificationChannel.SMS);
        verificationCode.setExpiresAt(LocalDateTime.now().plusMinutes(3));
        verificationCode.setCancelled(false);
        verificationCode.setPurpose(VerificationPurpose.REGISTER);
        verificationCode.setUsed(false);
        verificationCode.setIpAddress(resendPhoneVerification.getIpAddress());
        verificationCode.setUserAgent(resendPhoneVerification.getUserAgent());

        if (user.getVerificationCodes() == null) {
            user.setVerificationCodes(new ArrayList<>());
        }
        user.getVerificationCodes().add(verificationCode);

        verificationCodeRepository.save(verificationCode);
        userRepository.save(user);

        return new ResponseMessage("Yeniden doğrulama kodu gönderildi.", true);
    }

    @Override
    @Transactional
    public ResponseMessage verifyPhoneForPasswordReset(VerificationCodeRequest verificationCodeRequest) throws InvalidOrUsedVerificationCodeException, VerificationCodeExpiredException {
        String code = verificationCodeRequest.getCode();

        VerificationCode verificationCode = verificationCodeRepository
                .findFirstByCodeAndUsedFalseAndCancelledFalseOrderByCreatedAtDesc(code)
                .orElseThrow(InvalidOrUsedVerificationCodeException::new);

        if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new VerificationCodeExpiredException();
        }

        SecurityUser user = verificationCode.getUser();

        verificationCode.setUsed(true);
        verificationCodeRepository.save(verificationCode);

        UUID resetTokenUUID = UUID.randomUUID();

        PasswordResetToken passwordResetToken = new PasswordResetToken();
        passwordResetToken.setToken(resetTokenUUID.toString());
        passwordResetToken.setExpiresAt(LocalDateTime.now().plusMinutes(5)); // 5 dakika geçerli
        passwordResetToken.setUsed(false);
        passwordResetToken.setUser(user);

        passwordResetTokenRepository.save(passwordResetToken);

        return new ResponseMessage(resetTokenUUID + "", true);
    }

    @Override
    @Transactional
    public boolean updateFCMToken(String fcmToken, String username) throws UserNotFoundException {
        SecurityUser user = securityUserRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        user.getCurrentDeviceInfo().setFcmToken(fcmToken);
        return true;
    }


    @Override
    public List<FavoriteBusCardDTO> getFavoriteCards(String username) {
        List<UserFavoriteCard> favoriteCards = userRepository.findFavoriteCardsByUserNumber(username);
        return favoriteCards.stream().map(busCardConverter::favoriteBusCardToDTO).toList();
    }


    @Override
    @Transactional
    public ResponseMessage addFavoriteCard(String username, FavoriteCardRequest request) throws UserNotFoundException, BusCardNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        BusCard busCard = busCardRepository.findByCardNumberNative(request.getCardNumber())
                .orElseThrow(BusCardNotFoundException::new);

        boolean alreadyFavorited = user.getFavoriteCards().stream()
                .anyMatch(fav -> fav.getBusCard().getId().equals(busCard.getId()));
        if (alreadyFavorited) {
            return new ResponseMessage("Bu kart zaten favorilerinizde.", false);
        }

        UserFavoriteCard favorite = new UserFavoriteCard();
        favorite.setUser(user);
        favorite.setBusCard(busCard);
        favorite.setNickname(request.getNickname());
        favorite.setCreated(LocalDateTime.now());

        user.getFavoriteCards().add(favorite);
        userRepository.save(user);

        return new ResponseMessage("Kart favorilere başarıyla eklendi.", true);
    }

    @Override
    public ResponseMessage removeFavoriteCard(String username, String cardNumber) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        List<UserFavoriteCard> favoriteCards = user.getFavoriteCards();
        boolean isSuccess = favoriteCards.removeIf(fav ->
                fav.getBusCard() != null && fav.getBusCard().getCardNumber().equals(cardNumber)
        );

        if (isSuccess) {
            userRepository.save(user);
        }

        return new ResponseMessage("Favoriden silme işlemi " + (isSuccess ? "başarılı" : "başarısız"), isSuccess);
    }


    @Override
    @Transactional
    @JsonView(Views.User.class)
    public CacheUserDTO updateNotificationPreferences(String username, NotificationPreferencesDTO preferencesDto)
            throws UserNotFoundException {

        if (preferencesDto.getNotifyBeforeMinutes() != null && preferencesDto.getNotifyBeforeMinutes() < 0) {
            throw new IllegalArgumentException("Bildirim süresi negatif olamaz");
        }

        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);

        NotificationPreferences preferences = Optional.ofNullable(user.getNotificationPreferences())
                .orElseGet(NotificationPreferences::new);

        preferences.setPushEnabled(preferencesDto.isPushEnabled());
        preferences.setSmsEnabled(preferencesDto.isSmsEnabled());
        preferences.setEmailEnabled(preferencesDto.isEmailEnabled());
        preferences.setNotifyBeforeMinutes(preferencesDto.getNotifyBeforeMinutes());
        preferences.setFcmActive(preferencesDto.isFcmActive());

        user.setNotificationPreferences(preferences);
        userRepository.save(user);


        return userConverter.toCacheUserDTO(user);
    }



/*
    @Override
    public List<AuditLogDTO> getUserActivityLog(String username, Pageable pageable) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);


        Page<AuditLog> auditLogs = auditLogRepository.findByUser_UserNumberOrderByTimestampDesc(username, pageable);

        return auditLogs.stream()
                .map(autoTopUpConverter::convertToDTO) // Eğer farklı bir converter ise ona göre değiştir
                .toList();
    }



 */


    @Override
    public ResponseMessage setLowBalanceThreshold(String username, LowBalanceAlertRequest request) throws UserNotFoundException, BusCardNotFoundException, AlreadyBusCardLowBalanceException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        Optional<BusCard> busCard = busCardRepository.findById(request.getBusCardId());
        if (busCard.isEmpty()) {
            throw new BusCardNotFoundException();
        }
        boolean isPresent = user.getLowBalanceAlerts().containsKey(busCard.get());
        if (isPresent) {
            throw new AlreadyBusCardLowBalanceException();
        }
        user.getLowBalanceAlerts().put(busCard.get(), request.getLowBalance());

        return new ResponseMessage("düşük bakiye uyarısı ayarlandı", true);
    }

    @Override
    @JsonView(Views.User.class)
    public List<SearchHistoryDTO> getSearchHistory(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        return user.getSearchHistory().stream().filter(SearchHistory::isActive).map(userConverter::toSearchHistoryDTO).toList();
    }

    @Override
    public ResponseMessage clearSearchHistory(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        for (SearchHistory searchHistory : user.getSearchHistory()) {
            searchHistory.setActive(false);
            searchHistory.setDeleted(true);
            searchHistory.setDeletedAt(LocalDateTime.now());
        }
        return new ResponseMessage("arama geçmişi silindi", true);
    }


    @Override
    @JsonView(Views.User.class)
    public Page<AuditLogDTO> getUserActivityLog(String username, Pageable pageable) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        Page<AuditLog> auditLogsPage = auditLogRepository.findByUser(user, pageable);
        return auditLogsPage.map(auditLogConverter::mapToDto);
    }

    @Override
    @Transactional
    public ResponseMessage deleteProfilePhoto(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        if (user.getProfileInfo() != null) {
            user.getProfileInfo().setProfilePicture("https://thumbs.dreamstime.com/z/default-profile-picture-icon-high-resolution-high-resolution-default-profile-picture-icon-symbolizing-no-display-picture-360167031.jpg");
        }
        return new ResponseMessage("Profil fotoğrafı silindi", true);

    }

    @Override
    @Transactional
    public void updateLocation(String username, UpdateLocationRequest updateLocationRequest) throws UserNotFoundException {
        SecurityUser securityUser = securityUserRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        Location location = new Location();
        location.setUser(securityUser);
        location.setLatitude(updateLocationRequest.getLatitude());
        location.setLongitude(updateLocationRequest.getLongitude());
        location.setRecordedAt(LocalDateTime.now());
        securityUser.getLocationHistory().add(location);
        securityUser.setLastLocationUpdatedAt(LocalDateTime.now());
        securityUserRepository.save(securityUser);
    }

    @Override
    @Transactional
    public ResponseMessage verifyEmail(String token, String email, HttpServletRequest request)
            throws VerificationCodeExpiredException,
            VerificationCodeAlreadyUsedException,
            VerificationCodeCancelledException,
            VerificationCodeTypeMismatchException,
            UserNotFoundException,
            EmailMismatchException,
            InvalidVerificationCodeException {

        VerificationCode code = verificationCodeRepository
                .findFirstByCodeOrderByCreatedAtDesc(token)
                .orElseThrow(InvalidVerificationCodeException::new);

        if (code.isUsed()) {
            throw new VerificationCodeAlreadyUsedException();
        }

        if (code.isCancelled()) {
            throw new VerificationCodeCancelledException();
        }

        if (code.getExpiresAt().isBefore(LocalDateTime.now())) {
            code.setCancelled(true);
            verificationCodeRepository.save(code);
            throw new VerificationCodeExpiredException();
        }

        if (code.getPurpose() != VerificationPurpose.EMAIL_VERIFICATION) {
            throw new VerificationCodeTypeMismatchException();
        }

        SecurityUser securityUser = code.getUser();
        if (!(securityUser instanceof User user) || user.getProfileInfo() == null) {
            throw new UserNotFoundException();
        }

        String currentEmail = user.getProfileInfo().getEmail();
        if (currentEmail == null || !currentEmail.equalsIgnoreCase(email)) {
            throw new EmailMismatchException();
        }

        // Doğrulama işlemi
        user.setEmailVerified(true);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        code.setUsed(true);
        code.setVerifiedAt(LocalDateTime.now());
        verificationCodeRepository.save(code);

        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.EMAIL_VERIFICATION);

        updateDeviceInfoAndCreateAuditLog(
                user,
                request,
                geoIpService,
                ActionType.EMAIL_VERIFIED,
                "E-posta adresi doğrulandı.",
                null,
                "E-posta: " + email
        );


        fcmService.sendNotificationToToken(
                user,
                "E-Posta Doğrulandı",
                "E-posta adresiniz başarıyla doğrulandı.",
                NotificationType.SUCCESS,
                null
        );

        return new ResponseMessage("E-posta adresiniz başarıyla doğrulandı.", true);
    }

    @Override
    @Transactional
    public ResponseMessage deleteAccount(String username, DeleteAccountRequest request, HttpServletRequest httpRequest)
            throws ApproveIsConfirmDeletionException, UserNotFoundException, PasswordsDoNotMatchException, WalletBalanceNotZeroException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        if (user.getWallet() != null && user.getWallet().getBalance() != null) {
            if (user.getWallet().getBalance().compareTo(BigDecimal.ZERO) > 0) {
                throw new WalletBalanceNotZeroException();
            }
        }

        if (!request.isConfirmDeletion()) {
            throw new ApproveIsConfirmDeletionException();
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new PasswordsDoNotMatchException();
        }

        user.setDeleted(true);
        user.setStatus(UserStatus.DELETED);
        tokenRepository.deleteAllTokensByUser(user);
        userRepository.save(user);


        updateDeviceInfoAndCreateAuditLog(
                user,
                httpRequest,
                geoIpService,
                ActionType.DELETE_USER,
                "Kullanıcı hesap sildi. Sebep: " + (request.getReason() != null ? request.getReason() : "Belirtilmedi"),
                null,
                null
        );


        // Push bildirimi
        if (user.getNotificationPreferences() != null && user.getNotificationPreferences().isPushEnabled()) {
            fcmService.sendNotificationToToken(
                    user,
                    "Hesap Silme",
                    "Hesabınız başarıyla silindi. İyi günler dileriz.",
                    NotificationType.INFO,
                    null
            );
        }

        // SMS bildirimi
        if (user.getNotificationPreferences() != null && user.getNotificationPreferences().isSmsEnabled()) {
            String phone = user.getUserNumber();
            SmsRequest smsRequest = new SmsRequest();
            smsRequest.setTo(phone);
            smsRequest.setMessage("City Card: Hesabınız başarıyla silindi. Teşekkür ederiz.");
            smsService.sendSms(smsRequest);
        }

        // E-posta bildirimi
        if (user.getProfileInfo().getEmail() != null) {
            EmailMessage message = new EmailMessage();
            message.setToEmail(user.getProfileInfo().getEmail());
            message.setSubject("Hesap Silme Talebiniz Gerçekleştirildi");

            String body = """
                        <html>
                            <body style="font-family: Arial, sans-serif; color: #333;">
                                <h2>Sayın %s,</h2>
                                <p>Talebiniz üzerine <strong>%s</strong> tarihinde hesabınız başarıyla silinmiştir.</p>
                                <p>Silme sebebiniz: <em>%s</em></p>
                                <p>Hizmetlerimizi kullandığınız için teşekkür ederiz. Herhangi bir sorunuz olursa bizimle iletişime geçebilirsiniz.</p>
                                <br>
                                <p>Saygılarımızla,</p>
                                <p><strong>Destek Ekibi</strong></p>
                            </body>
                        </html>
                    """.formatted(
                    user.getProfileInfo().getName() + " " + user.getProfileInfo().getSurname(),
                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")),
                    request.getReason() != null ? request.getReason() : "Belirtilmedi"
            );

            message.setBody(body);
            message.setHtml(true);
            mailService.queueEmail(message);
        }

        return new ResponseMessage("Hesabınız silindi", true);
    }


    @Override
    @Transactional
    public ResponseMessage freezeAccount(String username, FreezeAccountRequest request, HttpServletRequest httpRequest) throws UserNotFoundException {

        User user = userRepository.findByUserNumber(username)
                .orElseThrow(UserNotFoundException::new);

        user.setStatus(UserStatus.FROZEN);
        userRepository.save(user);

        String ipAddress = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        updateDeviceInfoAndCreateAuditLog(
                user,
                httpRequest,
                geoIpService,
                ActionType.FREEZE_ACCOUNT,
                "Kullanıcı hesabını geçici olarak dondurdu.",
                null,
                null
        );


        String notificationTitle = "Hesap Dondurma";
        String notificationMessage = "Hesabınız başarıyla geçici olarak donduruldu.";

        NotificationPreferences prefs = user.getNotificationPreferences();

        if (prefs != null) {
            // Push bildirimi
            if (prefs.isPushEnabled()) {
                fcmService.sendNotificationToToken(
                        user,
                        notificationTitle,
                        notificationMessage,
                        NotificationType.INFO,
                        null
                );
            }

            // SMS bildirimi
            if (prefs.isSmsEnabled()) {
                String phone = user.getUserNumber();
                if (phone != null && !phone.isBlank()) {
                    SmsRequest smsRequest = new SmsRequest();
                    smsRequest.setTo(phone);
                    smsRequest.setMessage("City Card: " + notificationMessage);
                    smsService.sendSms(smsRequest);
                }
            }
        }

        // E-posta bildirimi
        if (user.getProfileInfo() != null && user.getProfileInfo().getEmail() != null) {
            EmailMessage message = new EmailMessage();
            message.setToEmail(user.getProfileInfo().getEmail());
            message.setSubject("Hesap Dondurma Bilgilendirmesi");

            String body = """
                        <html>
                            <body style="font-family: Arial, sans-serif; color: #333;">
                                <h2>Sayın %s,</h2>
                                <p>Talebiniz üzerine <strong>%s</strong> tarihinde hesabınız geçici olarak dondurulmuştur.</p>
                                <p>İşleminiz hakkında herhangi bir sorunuz varsa bizimle iletişime geçebilirsiniz.</p>
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

        return new ResponseMessage("Hesabınız başarıyla geçici olarak donduruldu.", true);
    }


    public String randomSixDigit() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000)); // 000000 ile 999999 arasında 6 hane
    }


}
