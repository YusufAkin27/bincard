package akin.city_card.security.manager;


import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.location.model.Location;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.entity.DeviceInfo;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.entity.Token;
import akin.city_card.security.entity.enums.TokenType;
import akin.city_card.security.exception.*;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.security.repository.TokenRepository;
import akin.city_card.security.service.JwtService;
import akin.city_card.sms.SmsService;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.user.model.LoginHistory;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.LoginHistoryRepository;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import akin.city_card.verification.model.VerificationChannel;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.verification.model.VerificationPurpose;
import akin.city_card.verification.repository.VerificationCodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.BeanUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class AuthManager implements AuthService {
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

    @Override
    @Transactional
    public ResponseMessage logout(String username) throws UserNotFoundException, TokenNotFoundException {
        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            throw new UserNotFoundException();
        }

        List<Token> tokens = tokenRepository.findAllBySecurityUserId(user.getId());
        if (tokens == null || tokens.isEmpty()) {
            throw new TokenNotFoundException();
        }

        tokenRepository.deleteAll(tokens);

        return new ResponseMessage("Çıkış başarılı", true);
    }

    @Override
    @Transactional
    public TokenResponseDTO phoneVerify(LoginPhoneVerifyCodeRequest phoneVerifyCode)
            throws InvalidVerificationCodeException,
            ExpiredVerificationCodeException,
            UsedVerificationCodeException,
            CancelledVerificationCodeException {

        VerificationCode verificationCode = verificationCodeRepository
                .findTopByCodeAndCancelledFalseOrderByCreatedAtDesc(phoneVerifyCode.getCode());

        if (verificationCode == null) {
            throw new InvalidVerificationCodeException();
        }

        if (verificationCode.isUsed()) {
            throw new UsedVerificationCodeException();
        }

        if (verificationCode.isCancelled()) {
            throw new CancelledVerificationCodeException();
        }

        if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ExpiredVerificationCodeException();
        }

        verificationCode.setUsed(true);
        verificationCodeRepository.save(verificationCode);

        SecurityUser user = verificationCode.getUser();
        tokenRepository.deleteBySecurityUserId(user.getId());


        securityUserRepository.save(user);

        return generateTokenResponse(user, verificationCode.getIpAddress(), verificationCode.getUserAgent());
    }


    @Override
    public ResponseMessage adminLogin(LoginRequestDTO loginRequestDTO) throws IncorrectPasswordException, UserRoleNotAssignedException, UserDeletedException, AdminNotApprovedException, UserNotActiveException, AdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(loginRequestDTO.getTelephone());
        loginRequestDTO.setTelephone(normalizedPhone);

        Admin admin = adminRepository.findByUserNumber(normalizedPhone);

        if (!passwordEncoder.matches(loginRequestDTO.getPassword(), admin.getPassword())) {
            throw new IncorrectPasswordException();
        }

        if (admin.getRoles() == null || admin.getRoles().isEmpty()) {
            throw new UserRoleNotAssignedException();
        }

        if (admin != null) {
            if (admin.isDeleted()) throw new UserDeletedException();
            if (!admin.isSuperAdminApproved()) throw new AdminNotApprovedException();
            if (!admin.isActive()) throw new UserNotActiveException();

            LoginMetadataDTO metadata = new LoginMetadataDTO();
            BeanUtils.copyProperties(loginRequestDTO, metadata);  // Spring framework'ten gelir
            applyLoginMetadataToUser(admin, metadata);

            // 5. Admin’i kaydet
            adminRepository.save(admin);
            sendLoginVerificationCode(admin.getUserNumber(), loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());
        } else {
            throw new AdminNotFoundException();
        }
        return new ResponseMessage("SMS gönderildi lütfen giriş için sms kodunu giriniz", true);
    }


    @Override
    public ResponseMessage superadminLogin(LoginRequestDTO loginRequestDTO) throws IncorrectPasswordException, UserRoleNotAssignedException, UserNotActiveException, UserDeletedException, SuperAdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(loginRequestDTO.getTelephone());
        loginRequestDTO.setTelephone(normalizedPhone);

        SuperAdmin superAdmin = superAdminRepository.findByUserNumber(normalizedPhone);

        if (!passwordEncoder.matches(loginRequestDTO.getPassword(), superAdmin.getPassword())) {
            throw new IncorrectPasswordException();
        }

        if (superAdmin.getRoles() == null || superAdmin.getRoles().isEmpty()) {
            throw new UserRoleNotAssignedException();
        }

        if (superAdmin != null) {
            if (superAdmin.isDeleted()) throw new UserDeletedException();
            if (!superAdmin.isActive()) throw new UserNotActiveException();

            LoginMetadataDTO metadata = new LoginMetadataDTO();
            BeanUtils.copyProperties(loginRequestDTO, metadata);  // Spring framework'ten gelir
            applyLoginMetadataToUser(superAdmin, metadata);

            // 5. Admin’i kaydet
            superAdminRepository.save(superAdmin);
            sendLoginVerificationCode(superAdmin.getUserNumber(), loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());
        } else {
            throw new SuperAdminNotFoundException();
        }
        return new ResponseMessage("SMS gönderildi lütfen giriş için sms kodunu giriniz", true);
    }

    @Override
    public TokenDTO refreshLogin(RefreshLoginRequest request) throws TokenIsExpiredException, TokenNotFoundException, InvalidRefreshTokenException, UserNotFoundException, IncorrectPasswordException {
        if (!jwtService.validateRefreshToken(request.getRefreshToken())) {
            throw new InvalidRefreshTokenException();
        }

        String userNumber = jwtService.getRefreshTokenClaims(request.getRefreshToken()).getSubject();

        Optional<SecurityUser> optionalSecurityUser = securityUserRepository.findByUserNumber(userNumber);

        if (optionalSecurityUser.isEmpty()) {
            throw new UserNotFoundException();
        }
        if (!passwordEncoder.matches(request.getPassword(), optionalSecurityUser.get().getPassword())) {
            throw new IncorrectPasswordException();
        }
        SecurityUser user = optionalSecurityUser.get();

        LoginMetadataDTO metadata = new LoginMetadataDTO();
        BeanUtils.copyProperties(request, metadata);  // Spring framework'ten gelir
        applyLoginMetadataToUser(user, metadata);
        // 5. Admin’i kaydet
        securityUserRepository.save(user);

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);

        String newAccessToken = jwtService.generateAccessToken(
                user,
                request.getIpAddress(),
                request.getDeviceInfo(),
                accessExpiry
        );

        return new TokenDTO(
                newAccessToken,
                issuedAt,
                accessExpiry,
                issuedAt,
                request.getIpAddress(),
                request.getDeviceInfo(),
                TokenType.ACCESS
        );
    }

    @Override
    public ResponseMessage resendVerifyCode(String telephone) throws UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException {
        telephone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(telephone);
        SecurityUser user = securityUserRepository.findByUserNumber(telephone).orElseThrow(UserNotFoundException::new);
        sendLoginVerificationCode(telephone, user.getDeviceInfo().getIpAddress(), null);
        return new ResponseMessage("yeni doğrulama kodu gönderildi", true);
    }

    @Override
    @Transactional
    public TokenResponseDTO login(LoginRequestDTO loginRequestDTO)
            throws NotFoundUserException, UserDeletedException, UserNotActiveException,
            IncorrectPasswordException, UserRoleNotAssignedException, PhoneNotVerifiedException,
            UnrecognizedDeviceException, AdminNotApprovedException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException {

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(loginRequestDTO.getTelephone());
        loginRequestDTO.setTelephone(normalizedPhone);

        SecurityUser securityUser = securityUserRepository.findByUserNumber(normalizedPhone)
                .orElseThrow(NotFoundUserException::new);

        if (!passwordEncoder.matches(loginRequestDTO.getPassword(), securityUser.getPassword())) {
            throw new IncorrectPasswordException();
        }

        if (securityUser.getRoles() == null || securityUser.getRoles().isEmpty()) {
            throw new UserRoleNotAssignedException();
        }

        if (securityUser instanceof User user) {
            if (!user.isActive()) {
                throw new UserNotActiveException();
            }

            if (!user.isPhoneVerified()) {
                sendLoginVerificationCode(user.getUserNumber(), loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());
                throw new PhoneNotVerifiedException();
            }

            String currentDevice = loginRequestDTO.getDeviceInfo();
            String lastDevice = null;

            List<LoginHistory> loginHistory = user.getLoginHistory();
            if (loginHistory != null && !loginHistory.isEmpty()) {
                lastDevice = loginHistory.get(0).getDevice();  // En güncel giriş
            }

            if (lastDevice != null && !lastDevice.equals(currentDevice)) {
                sendLoginVerificationCode(user.getUserNumber(), loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());
                throw new UnrecognizedDeviceException();
            }

            // ✔ Token oluştur
            TokenResponseDTO tokenResponseDTO = generateTokenResponse(
                    user,
                    loginRequestDTO.getIpAddress(),
                    loginRequestDTO.getDeviceInfo()
            );

            LoginMetadataDTO metadata = new LoginMetadataDTO();
            BeanUtils.copyProperties(loginRequestDTO, metadata);  // Spring framework'ten gelir
            applyLoginMetadataToUser(user, metadata);

            securityUserRepository.save(user);

            return tokenResponseDTO;
        }

        throw new NotFoundUserException();
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
            user.getLocationHistory().add(location);
        }

        DeviceInfo updatedDeviceInfo = DeviceInfo.builder()
                .ipAddress(metadata.getIpAddress())
                .deviceUuid(metadata.getDeviceUuid())
                .fcmToken(metadata.getFcmToken())
                .build();
        user.setDeviceInfo(updatedDeviceInfo);

        user.setLastLocationUpdatedAt(LocalDateTime.now());

        user.getLoginHistory().add(history);
    }


    public TokenResponseDTO generateTokenResponse(SecurityUser user, String ipAddress, String deviceInfo) {
        tokenRepository.deleteBySecurityUserId(user.getId());

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);
        LocalDateTime refreshExpiry = issuedAt.plusDays(7);

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

        return new TokenResponseDTO(accessToken, refreshToken);
    }


    private void sendLoginVerificationCode(String telephone, String ipAddress, String userAgent)
            throws UserNotFoundException, VerificationCooldownException, VerificationCodeStillValidException {

        SecurityUser user = securityUserRepository.findByUserNumber(telephone)
                .orElseThrow(UserNotFoundException::new);

        LocalDateTime now = LocalDateTime.now();

        // 1. En son LOGIN kodunu getir
        VerificationCode lastCode = verificationCodeRepository.findAll().stream()
                .filter(vc -> vc.getUser().getId().equals(user.getId())
                        && vc.getPurpose() == VerificationPurpose.LOGIN)
                .max(Comparator.comparing(VerificationCode::getCreatedAt))
                .orElse(null);

        // 2. Kod hâlâ geçerliyse: yeni kod gönderme, kullanıcıdan mevcut kodu girmesini iste
        if (lastCode != null && !lastCode.isUsed() && !lastCode.isCancelled() && lastCode.getExpiresAt().isAfter(now)) {
            Duration timeSinceSent = Duration.between(lastCode.getCreatedAt(), now);
            long secondsSinceSent = timeSinceSent.toSeconds();
            long cooldownSeconds = 180; // 3 dakika
            long remainingSeconds = cooldownSeconds - secondsSinceSent;

            if (remainingSeconds > 0) {
                throw new VerificationCooldownException(remainingSeconds); // Süre dolmamış
            }

            throw new VerificationCodeStillValidException(); // Süre dolmuş ama kod hâlâ geçerli
        }

        // 3. Tüm eski LOGIN kodlarını iptal et (önceki aktifleri geçersiz yap)
        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.LOGIN);

        // 4. Yeni kod oluştur
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

        // SMS servis entegrasyonu
    /*
    SmsRequest smsRequest = new SmsRequest();
    smsRequest.setMessage(verificationCode.getCode());
    smsRequest.setTo(request.getTelephone());
    smsService.sendSms(smsRequest);
    */

        System.out.println("📩 Yeni gönderilen kod: " + code);
    }



    public String randomSixDigit() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000)); // 000000 ile 999999 arasında 6 hane
    }

    @Override
    public TokenDTO updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) throws UserNotFoundException, InvalidRefreshTokenException, TokenIsExpiredException, TokenNotFoundException {
        if (!jwtService.validateRefreshToken(updateAccessTokenRequestDTO.getRefreshToken())) {
            throw new InvalidRefreshTokenException();
        }

        String userNumber = jwtService.getRefreshTokenClaims(updateAccessTokenRequestDTO.getRefreshToken()).getSubject();

        SecurityUser user = securityUserRepository.findByUserNumber(userNumber)
                .orElseThrow(UserNotFoundException::new);
        LoginMetadataDTO metadata = new LoginMetadataDTO();
        BeanUtils.copyProperties(updateAccessTokenRequestDTO, metadata);  // Spring framework'ten gelir
        applyLoginMetadataToUser(user, metadata);

        // ✔ Kalıcı hale getir
        securityUserRepository.save(user);

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);

        String newAccessToken = jwtService.generateAccessToken(
                user,
                updateAccessTokenRequestDTO.getIpAddress(),
                updateAccessTokenRequestDTO.getDeviceInfo(),
                accessExpiry
        );

        return new TokenDTO(
                newAccessToken,
                issuedAt,
                accessExpiry,
                issuedAt,
                updateAccessTokenRequestDTO.getIpAddress(),
                updateAccessTokenRequestDTO.getDeviceInfo(),
                TokenType.ACCESS
        );
    }


}
