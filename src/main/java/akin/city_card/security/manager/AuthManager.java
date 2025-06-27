package akin.city_card.security.manager;


import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.driver.model.Driver;
import akin.city_card.driver.repository.DriverRepository;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.entity.Token;
import akin.city_card.security.entity.enums.TokenType;
import akin.city_card.security.exception.*;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.security.repository.TokenRepository;
import akin.city_card.security.service.JwtService;
import akin.city_card.sms.SmsRequest;
import akin.city_card.sms.SmsService;
import akin.city_card.superadmin.model.SuperAdmin;
import akin.city_card.superadmin.repository.SuperAdminRepository;
import akin.city_card.user.exceptions.UserIsNotPhoneVerifyException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.service.concretes.PhoneNumberFormatter;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import akin.city_card.verification.model.VerificationChannel;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.verification.model.VerificationPurpose;
import akin.city_card.verification.repository.VerificationCodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
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
    private final DriverRepository driverRepository;


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
    public TokenResponseDTO phoneVerify(LoginPhoneVerifyCodeRequest phoneVerifyCode) throws ExpiredVerificationCodeException {
        VerificationCode verificationCode = verificationCodeRepository
                .findTopByCodeAndCancelledFalseAndUsedFalseOrderByCreatedAtDesc(phoneVerifyCode.getCode());

        if (verificationCode == null || verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ExpiredVerificationCodeException();
        }

        verificationCode.setUsed(true);
        verificationCodeRepository.save(verificationCode);

        User user = verificationCode.getUser();
        tokenRepository.deleteBySecurityUserId(user.getId());

        user.setLastLoginDevice(phoneVerifyCode.getDeviceInfo());
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(phoneVerifyCode.getIpAddress());
        user.setLastLoginAppVersion(phoneVerifyCode.getAppVersion());
        user.setLastLoginPlatform(phoneVerifyCode.getPlatform());
        userRepository.save(user);

        return generateTokenResponse(user, verificationCode.getIpAddress(), verificationCode.getUserAgent());

    }


    @Override
    @Transactional
    public TokenResponseDTO login(LoginRequestDTO loginRequestDTO)
            throws NotFoundUserException, UserDeletedException, UserNotActiveException,
            IncorrectPasswordException, UserRoleNotAssignedException, PhoneNotVerifiedException, UnrecognizedDeviceException {

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
                sendLoginVerificationCode(user, loginRequestDTO);
                throw new PhoneNotVerifiedException();
            }

            String currentDevice = loginRequestDTO.getDeviceInfo();
            String lastDevice = user.getLastLoginDevice();

            if (lastDevice != null && !lastDevice.equals(currentDevice)) {
                sendLoginVerificationCode(user, loginRequestDTO);
                throw new UnrecognizedDeviceException();
            }

            TokenResponseDTO tokenResponseDTO = generateTokenResponse(user, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());


            user.setLastLoginDevice(currentDevice);
            user.setLastLoginAt(LocalDateTime.now());
            user.setLastLoginIp(loginRequestDTO.getIpAddress());
            user.setLastLoginAppVersion(loginRequestDTO.getAppVersion());
            user.setLastLoginPlatform(loginRequestDTO.getPlatform());

            userRepository.save(user);

            return tokenResponseDTO;
        } else if (securityUser instanceof Admin admin) {
            if (admin.isDeleted()) {
                throw new UserDeletedException();
            }

            if (!admin.isActive()) {
                throw new UserNotActiveException();
            }

            TokenResponseDTO tokenResponseDTO = generateTokenResponse(admin, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());

            admin.setLastLoginAt(LocalDateTime.now());
            admin.setIpAddress(loginRequestDTO.getIpAddress());
            admin.setDeviceUuid(loginRequestDTO.getDeviceInfo());

            adminRepository.save(admin);

            return tokenResponseDTO;

        } else if (securityUser instanceof SuperAdmin superAdmin) {
            if (superAdmin.isDeleted()) {
                throw new UserDeletedException();
            }

            if (!superAdmin.isActive()) {
                throw new UserNotActiveException();
            }

            TokenResponseDTO tokenResponseDTO = generateTokenResponse(superAdmin, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());


            superAdmin.setLastLoginAt(LocalDateTime.now());
            superAdmin.setLastLoginIp(loginRequestDTO.getIpAddress());
            superAdmin.setDeviceUuid(loginRequestDTO.getDeviceInfo());

            superAdminRepository.save(superAdmin);

            return tokenResponseDTO;
        } else if (securityUser instanceof Driver driver) {
            if (!driver.isActive()) {
                throw new UserNotActiveException();
            }

            TokenResponseDTO tokenResponseDTO = generateTokenResponse(driver, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());
            driver.setLastLoginAt(LocalDateTime.now());
            driver.setIpAddress(loginRequestDTO.getIpAddress());
            driver.setDeviceUuid(loginRequestDTO.getDeviceInfo());

            driverRepository.save(driver);

            return tokenResponseDTO;
        }


        throw new NotFoundUserException();
    }

    public TokenResponseDTO generateTokenResponse(SecurityUser user, String ipAddress, String deviceInfo) {
        // Mevcut tokenları sil
        tokenRepository.deleteBySecurityUserId(user.getId());

        // Sabit zaman belirleniyor
        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(5);
        LocalDateTime refreshExpiry = issuedAt.plusDays(7);

        // Token'ları oluştur
        String accessTokenValue = jwtService.generateAccessToken(user, ipAddress, deviceInfo,  accessExpiry);
        String refreshTokenValue = jwtService.generateRefreshToken(user, ipAddress, deviceInfo, refreshExpiry);

        // Token nesneleri oluşturuluyor
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



    private void sendLoginVerificationCode(User user, LoginRequestDTO request) {
        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.LOGIN);

        String code = randomSixDigit();

        VerificationCode verificationCode = VerificationCode.builder()
                .code(code)
                .user(user)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(3))
                .channel(VerificationChannel.SMS)
                .attemptCount(0)
                .used(false)
                .cancelled(false)
                .purpose(VerificationPurpose.LOGIN)
                .ipAddress(request.getIpAddress())
                .userAgent(request.getDeviceInfo())
                .build();

        verificationCodeRepository.save(verificationCode);
        System.out.println("Gönderilen kod :" + code);
        // SMS gönder
        /*
        SmsRequest smsRequest = new SmsRequest();
        smsRequest.setTo(user.getUserNumber());
        smsRequest.setMessage("City Card - Giriş için doğrulama kodunuz: " + code + ". Kod 3 dakika geçerlidir.");
        smsService.sendSms(smsRequest);

         */
    }


    public String randomSixDigit() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000)); // 000000 ile 999999 arasında 6 hane
    }

    @Override
    public ResponseEntity<?> updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) {
        try {
            // Refresh token geçerliliğini kontrol et
            if (!jwtService.validateRefreshToken(updateAccessTokenRequestDTO.getRefreshToken())) {
                throw new InvalidRefreshTokenException();
            }

            // Token'dan kullanıcı numarasını al
            String userNumber = jwtService.getRefreshTokenClaims(updateAccessTokenRequestDTO.getRefreshToken()).getSubject();

            // Kullanıcıyı getir
            User user = userRepository.findByUserNumber(userNumber);
            if (user == null) {
                throw new UserNotFoundException();
            }

            // Access token süresi belirle (örneğin 5 dakika)
            LocalDateTime accessExpiry = LocalDateTime.now().plusMinutes(5);

            // Yeni access token üret
            String newAccessToken = jwtService.generateAccessToken(
                    user,
                    updateAccessTokenRequestDTO.getIpAddress(),
                    updateAccessTokenRequestDTO.getDeviceInfo(),
                    accessExpiry
            );

            // Yeni access token'ı response ile döndür
            return ResponseEntity.ok(new AccessTokenResponse(newAccessToken));

        } catch (InvalidRefreshTokenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Refresh token geçersiz: " + e.getMessage());
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Kullanıcı hatası: " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Bir hata meydana geldi: " + e.getMessage());
        }
    }




}
