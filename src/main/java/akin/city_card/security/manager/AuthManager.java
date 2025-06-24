package akin.city_card.security.manager;


import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.*;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.security.repository.TokenRepository;
import akin.city_card.security.service.JwtService;
import akin.city_card.sms.SmsRequest;
import akin.city_card.sms.SmsService;
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


    @Override
    @Transactional
    public ResponseMessage logout(String username) throws UserNotFoundException {
        User student = userRepository.findByUserNumber(username);
        tokenRepository.deleteAllBySecurityUser_Id(student.getId());


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

        // 🔐 Yeni cihaz/IP artık doğrulanmış sayılıyor → Güncelle
        user.setLastLoginDevice(phoneVerifyCode.getDeviceInfo());
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIp(phoneVerifyCode.getIpAddress());
        user.setLastLoginAppVersion(phoneVerifyCode.getAppVersion());
        user.setLastLoginPlatform(phoneVerifyCode.getPlatform());
        userRepository.save(user);

        tokenRepository.deleteBySecurityUserId(user.getId());

        String accessToken = jwtService.generateAccessToken(user, phoneVerifyCode.getIpAddress(), phoneVerifyCode.getDeviceInfo());
        String refreshToken = jwtService.generateRefreshToken(user, phoneVerifyCode.getIpAddress(), phoneVerifyCode.getDeviceInfo());

        return new TokenResponseDTO(accessToken, refreshToken);
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

        // Şifre kontrolü
        if (!passwordEncoder.matches(loginRequestDTO.getPassword(), securityUser.getPassword())) {
            throw new IncorrectPasswordException();
        }

        // Roller kontrolü
        if (securityUser.getRoles() == null || securityUser.getRoles().isEmpty()) {
            throw new UserRoleNotAssignedException();
        }

        // Kullanıcı tipi ayırımı
        if (securityUser instanceof User user) {
            // Kullanıcı aktif mi?
            if (!user.isActive()) {
                throw new UserNotActiveException();
            }

            // Telefon doğrulandı mı?
            if (!user.isPhoneVerified()) {
                sendLoginVerificationCode(user, loginRequestDTO);
                throw new PhoneNotVerifiedException();
            }

            // Cihaz kontrolü
            String currentDevice = loginRequestDTO.getDeviceInfo();
            String lastDevice = user.getLastLoginDevice();

            if (lastDevice != null && !lastDevice.equals(currentDevice)) {
                sendLoginVerificationCode(user, loginRequestDTO);
                throw new UnrecognizedDeviceException();
            }

            // Token sil ve oluştur
            tokenRepository.deleteBySecurityUserId(user.getId());

            String accessToken = jwtService.generateAccessToken(user, loginRequestDTO.getIpAddress(), currentDevice);
            String refreshToken = jwtService.generateRefreshToken(user, loginRequestDTO.getIpAddress(), currentDevice);

            user.setLastLoginDevice(currentDevice);
            user.setLastLoginAt(LocalDateTime.now());
            user.setLastLoginIp(loginRequestDTO.getIpAddress());
            user.setLastLoginAppVersion(loginRequestDTO.getAppVersion());
            user.setLastLoginPlatform(loginRequestDTO.getPlatform());

            userRepository.save(user);

            return new TokenResponseDTO(accessToken, refreshToken);

        } else if (securityUser instanceof Admin admin) {
            // Admin silinmiş mi?
            if (admin.isDeleted()) {
                throw new UserDeletedException();
            }

            // Admin aktif mi?
            if (!admin.isActive()) {
                throw new UserNotActiveException();
            }

            // Token sil ve oluştur
            tokenRepository.deleteBySecurityUserId(admin.getId());

            String accessToken = jwtService.generateAccessToken(admin, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());
            String refreshToken = jwtService.generateRefreshToken(admin, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());

            admin.setLastLoginAt(LocalDateTime.now());
            admin.setIpAddress(loginRequestDTO.getIpAddress());
            admin.setDeviceUuid(loginRequestDTO.getDeviceInfo());

            adminRepository.save(admin);

            return new TokenResponseDTO(accessToken, refreshToken);
        }

        throw new NotFoundUserException(); // Ne User ne Admin değilse
    }


    private void sendLoginVerificationCode(User user, LoginRequestDTO request) {
        // Eski kodları iptal et
        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.LOGIN);

        // Yeni kod oluştur
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
            if (!jwtService.validateRefreshToken(updateAccessTokenRequestDTO.getRefreshToken())) {
                throw new InvalidRefreshTokenException();
            }

            String userNumber = jwtService.getRefreshTokenClaims(updateAccessTokenRequestDTO.getRefreshToken()).getSubject();
            User user = userRepository.findByUserNumber(userNumber);


            String ipAddress = updateAccessTokenRequestDTO.getIpAddress();
            String deviceInfo = updateAccessTokenRequestDTO.getDeviceInfo();
            String newAccessToken = jwtService.generateAccessToken(user, ipAddress, deviceInfo);

            return ResponseEntity.ok(new AccessTokenResponse(newAccessToken));
        } catch (TokenNotFoundException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token bulunamadı: " + e.getMessage());
        } catch (InvalidRefreshTokenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Refresh token geçersiz: " + e.getMessage());
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Kullanıcı hatası: " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Bir hata meydana geldi: " + e.getMessage());
        }
    }


}
