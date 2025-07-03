package akin.city_card.security.manager;


import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.admin.model.Admin;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.location.model.Location;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
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
    public ResponseMessage adminLogin(LoginRequestDTO loginRequestDTO) throws IncorrectPasswordException, UserRoleNotAssignedException, UserDeletedException, AdminNotApprovedException, UserNotActiveException, AdminNotFoundException {
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

            sendLoginVerificationCode(admin, loginRequestDTO);
        } else {
            throw new AdminNotFoundException();
        }
        return new ResponseMessage("SMS gönderildi lütfen giriş için sms kodunu giriniz", true);
    }


    @Override
    public ResponseMessage superadminLogin(LoginRequestDTO loginRequestDTO) throws IncorrectPasswordException, UserRoleNotAssignedException, UserNotActiveException, UserDeletedException, SuperAdminNotFoundException {
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

            sendLoginVerificationCode(superAdmin, loginRequestDTO);
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

        Optional<SecurityUser> user = securityUserRepository.findByUserNumber(userNumber);

        if (user.isEmpty()) {
            throw new UserNotFoundException();
        }
        if (!passwordEncoder.matches(request.getPassword(), user.get().getPassword())) {
            throw new IncorrectPasswordException();
        }

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);

        String newAccessToken = jwtService.generateAccessToken(
                user.orElse(null),
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
    @Transactional
    public TokenResponseDTO login(LoginRequestDTO loginRequestDTO)
            throws NotFoundUserException, UserDeletedException, UserNotActiveException,
            IncorrectPasswordException, UserRoleNotAssignedException, PhoneNotVerifiedException, UnrecognizedDeviceException, AdminNotApprovedException {

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

            String lastDevice = null;
            List<LoginHistory> loginHistory = user.getLoginHistory();

            if (loginHistory != null && !loginHistory.isEmpty()) {
                lastDevice = loginHistory.get(0).getDevice();  // İlk kayıt, en güncel login history
            }

            if (lastDevice != null && !lastDevice.equals(currentDevice)) {
                sendLoginVerificationCode(user, loginRequestDTO);
                throw new UnrecognizedDeviceException();
            }

            TokenResponseDTO tokenResponseDTO = generateTokenResponse(user, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());


            Location location = Location.builder()
                    .latitude(loginRequestDTO.getLatitude())
                    .longitude(loginRequestDTO.getLongitude())
                    .recordedAt(LocalDateTime.now())
                    .build();

            LoginHistory loginHistory1 = LoginHistory.builder()
                    .user(user)
                    .loginAt(LocalDateTime.now())
                    .ipAddress(loginRequestDTO.getIpAddress())
                    .device(currentDevice)
                    .platform(loginRequestDTO.getPlatform())
                    .appVersion(loginRequestDTO.getAppVersion())
                    .location(location)
                    .build();

            loginHistoryRepository.save(loginHistory1);


            return tokenResponseDTO;
        }

        throw new NotFoundUserException();
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


    private void sendLoginVerificationCode(SecurityUser user, LoginRequestDTO request) {
        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.LOGIN);

        String code = randomSixDigit();

        VerificationCode verificationCode = VerificationCode.builder()
                .code(code)
                .user(user)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(3))
                .channel(VerificationChannel.SMS)
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
    public TokenDTO updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) throws UserNotFoundException, InvalidRefreshTokenException, TokenIsExpiredException, TokenNotFoundException {
        if (!jwtService.validateRefreshToken(updateAccessTokenRequestDTO.getRefreshToken())) {
            throw new InvalidRefreshTokenException();
        }

        String userNumber = jwtService.getRefreshTokenClaims(updateAccessTokenRequestDTO.getRefreshToken()).getSubject();

        Optional<SecurityUser> user = securityUserRepository.findByUserNumber(userNumber);

        if (user.isEmpty()) {
            throw new UserNotFoundException();
        }

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime accessExpiry = issuedAt.plusMinutes(15);

        String newAccessToken = jwtService.generateAccessToken(
                user.orElse(null),
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
