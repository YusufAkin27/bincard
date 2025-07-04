package akin.city_card.user.service.concretes;

import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.mail.MailService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotActiveException;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.exception.VerificationCodeStillValidException;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.sms.SmsService;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.model.PasswordResetToken;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.PasswordResetTokenRepository;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.rules.UserRules;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import akin.city_card.verification.exceptions.InvalidOrUsedVerificationCodeException;
import akin.city_card.verification.model.VerificationChannel;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.verification.model.VerificationPurpose;
import akin.city_card.verification.repository.VerificationCodeRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@Service
@RequiredArgsConstructor
public class UserManager implements UserService {
    private final UserRepository userRepository;
    private final UserConverter userConverter;
    private final SmsService smsService;
    private final MailService mailService;
    private final MediaUploadService mediaUploadService;
    private final UserRules userRules;
    private final VerificationCodeRepository verificationCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final SecurityUserRepository securityUserRepository;


    @Override
    @Transactional
    public ResponseMessage create(CreateUserRequest request) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException, VerificationCodeStillValidException {

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(request.getTelephone());
        request.setTelephone(normalizedPhone);

        Optional<SecurityUser> existingUserOpt = securityUserRepository.findByUserNumber(request.getTelephone());

        if (existingUserOpt.isPresent()) {
            SecurityUser existingUser = existingUserOpt.get();

            if (existingUser.isEnabled()) {
                throw new PhoneNumberAlreadyExistsException();
            }

            LocalDateTime now = LocalDateTime.now();

            VerificationCode lastCode = verificationCodeRepository.findAll().stream()
                    .filter(vc -> vc.getUser().getId().equals(existingUser.getId()) &&
                            vc.getPurpose() == VerificationPurpose.REGISTER)
                    .max(Comparator.comparing(VerificationCode::getCreatedAt))
                    .orElse(null);

            if (lastCode != null && !lastCode.isUsed() && !lastCode.isCancelled() && lastCode.getExpiresAt().isAfter(now)) {
                throw new VerificationCodeStillValidException();
            }

            verificationCodeRepository.cancelAllActiveCodes(existingUser.getId(), VerificationPurpose.REGISTER);

            sendVerificationCode(existingUser, request.getIpAddress(), request.getUserAgent(), VerificationPurpose.REGISTER);

            return new ResponseMessage("Telefon numarası daha önce kayıt olmuş ancak aktif edilmemiş. Yeni doğrulama kodu gönderildi.", true);
        }

        userRules.checkPhoneIsUnique(request.getTelephone());

        User user = userConverter.convertUserToCreateUser(request);
        System.out.println(user.toString());

        userRepository.save(user);

        sendVerificationCode(user, request.getIpAddress(), request.getUserAgent(), VerificationPurpose.REGISTER);

        return new ResponseMessage("Kullanıcı başarıyla oluşturuldu. Doğrulama kodu SMS olarak gönderildi.", true);
    }

    private void sendVerificationCode(SecurityUser user, String ipAddress, String userAgent, VerificationPurpose purpose) {
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
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        verificationCodeRepository.save(verificationCode);

        // SmsRequest smsRequest = new SmsRequest();
        // smsRequest.setTo(user.getUserNumber());
        // smsRequest.setMessage("City Card - Doğrulama kodunuz: " + code + ". Kod 3 dakika geçerlidir.");
        // smsService.sendSms(smsRequest);

        System.out.println("📩 Yeni kayıt doğrulama kodu: " + code);
    }



    @Override
    @Transactional
    public ResponseMessage verifyPhone(VerificationCodeRequest request) throws UserNotFoundException {
        VerificationCode verificationCode = verificationCodeRepository
                .findTopByCodeOrderByCreatedAtDesc(request.getCode());

        if (verificationCode == null) {
            return new ResponseMessage("Böyle bir doğrulama kodu bulunamadı.", false);
        }

        if (verificationCode.isUsed()) {
            return new ResponseMessage("Bu doğrulama kodu zaten kullanılmış.", false);
        }

        if (verificationCode.isCancelled()) {
            return new ResponseMessage("Bu doğrulama kodu iptal edilmiş.", false);
        }

        if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            verificationCode.setCancelled(true);
            verificationCodeRepository.save(verificationCode);
            return new ResponseMessage("Doğrulama kodunun süresi dolmuş.", false);
        }

        SecurityUser securityUser = verificationCode.getUser();
        if (!(securityUser instanceof User user)) {
            throw new UserNotFoundException();
        }

        user.setPhoneVerified(true);
        user.setActive(true);
        userRepository.save(user);

        verificationCode.setUsed(true);
        verificationCode.setVerifiedAt(LocalDateTime.now());
        verificationCodeRepository.save(verificationCode);

        verificationCodeRepository.cancelAllActiveCodes(user.getId(), VerificationPurpose.REGISTER);

        return new ResponseMessage("Telefon numarası başarıyla doğrulandı. Hesabınız aktif hale getirildi.", true);
    }


    @Override
    public UserDTO getProfile(String username) throws UserNotFoundException {
        return userConverter.convertUserToDTO(userRepository.findByUserNumber(username));
    }

    @Override
    @Transactional
    public ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);

        boolean isUpdated = false;

        if (updateProfileRequest.getName() != null &&
                !updateProfileRequest.getName().equals(user.getProfileInfo().getName())) {
            user.getProfileInfo().setName(updateProfileRequest.getName());
            isUpdated = true;
        }

        if (updateProfileRequest.getSurname() != null &&
                !updateProfileRequest.getSurname().equals(user.getProfileInfo().getSurname())) {
            user.getProfileInfo().setSurname(updateProfileRequest.getSurname());
            isUpdated = true;
        }
        if (updateProfileRequest.getEmail() != null && !updateProfileRequest.getEmail().isBlank()) {
            user.getProfileInfo().setEmail(user.getProfileInfo().getEmail().trim().toLowerCase());
            isUpdated = true;
        }


        if (isUpdated) {
            userRepository.save(user);
            return new ResponseMessage("Profil başarıyla güncellendi.", true);
        }

        return new ResponseMessage("Herhangi bir değişiklik yapılmadı.", false);
    }


    @Override
    public ResponseMessage deactivateUser(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        user.setActive(false);
        user.setDeleted(true);
        return new ResponseMessage("Kullanıcı hesabı silindi.", true);
    }

    @Override
    public List<ResponseMessage> createAll(List<CreateUserRequest> createUserRequests) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException, VerificationCodeStillValidException {
        List<ResponseMessage> responseMessages = new ArrayList<>();
        for (CreateUserRequest createUserRequest : createUserRequests) {
            responseMessages.add(create(createUserRequest));
        }

        return responseMessages;

    }

    @Override
    @Transactional
    public ResponseMessage updateProfilePhoto(String username, MultipartFile file)
            throws PhotoSizeLargerException, IOException, UserNotFoundException {

        User user = userRepository.findByUserNumber(username);

        try {
            CompletableFuture<String> futureUrl = mediaUploadService.uploadAndOptimizeMedia(file);
            String imageUrl = futureUrl.get();

            user.getProfileInfo().setProfilePicture(imageUrl);

            userRepository.save(user);

            return new ResponseMessage("Profil fotoğrafı başarıyla güncellendi.", true);

        } catch (InterruptedException | ExecutionException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Fotoğraf yüklenirken bir hata oluştu.", e);
        } catch (OnlyPhotosAndVideosException | VideoSizeLargerException | FileFormatCouldNotException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public ResponseMessage sendPasswordResetCode(String phone) throws UserNotFoundException {
        Optional<SecurityUser> user = securityUserRepository.findByUserNumber(PhoneNumberFormatter.normalizeTurkishPhoneNumber(phone));
        if (user.isEmpty()) {
            throw new UserNotFoundException();
        }
        String code = randomSixDigit();
        System.out.println("Doğrulama kodu: " + code);

        VerificationCode verificationCode = VerificationCode.builder()
                .user(user.get())
                .code(code)
                .channel(VerificationChannel.SMS)
                .purpose(VerificationPurpose.RESET_PASSWORD)
                .expiresAt(LocalDateTime.now().plusMinutes(3))
                .build();


        verificationCodeRepository.save(verificationCode);

        // SMS gönder
        /*
        SmsRequest smsRequest = new SmsRequest();
        smsRequest.setTo(phone);
        smsRequest.setMessage("City Card - Doğrulama kodunuz: " + code +
                ". Kod 3 dakika boyunca geçerlidir.");
        smsService.sendSms(smsRequest);

         */
        return new ResponseMessage("Doğrulama kodu gönderildi.", true);
    }

    @Override
    public ResponseMessage resetPassword(PasswordResetRequest request)
            throws PasswordResetTokenNotFoundException,
            PasswordResetTokenExpiredException,
            PasswordResetTokenIsUsedException, SamePasswordException {

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

        return new ResponseMessage("Şifreniz başarıyla sıfırlandı.", true);
    }


    @Override
    public ResponseMessage changePassword(String username, ChangePasswordRequest request)
            throws UserIsDeletedException, UserNotActiveException, UserNotFoundException, PasswordsDoNotMatchException, InvalidNewPasswordException, IncorrectCurrentPasswordException, SamePasswordException {

        User user = userRepository.findByUserNumber(username);
        if (user == null) {
            throw new UserNotFoundException();
        }

        if (!user.isActive()) {
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

        return new ResponseMessage("Şifre başarıyla güncellendi.", true);
    }


    @Override
    public ResponseMessage resendPhoneVerificationCode(ResendPhoneVerificationRequest resendPhoneVerification) throws UserNotFoundException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(resendPhoneVerification.getTelephone());
        resendPhoneVerification.setTelephone(normalizedPhone);

        User user = userRepository.findByUserNumber(resendPhoneVerification.getTelephone());
        if (user == null) {
            throw new UserNotFoundException();
        }

        String code = randomSixDigit();

        /*// SMS gönderimi
        SmsRequest smsRequest = new SmsRequest();
        smsRequest.setTo(resendPhoneVerification.getTelephone());
        smsRequest.setMessage("City Card - Doğrulama kodunuz: " + code +
                ". Kod 3 dakika boyunca geçerlidir.");
        smsService.sendSms(smsRequest);

         */

        // Doğrulama kodu bilgisi oluştur ve kaydet
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

        // Burada null olma ihtimaline karşı verificationCodes listesini kontrol et
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
    public ResponseMessage verifyPhoneForPasswordReset(VerificationCodeRequest verificationCodeRequest) throws InvalidOrUsedVerificationCodeException, ExpiredVerificationCodeException {
        String code = verificationCodeRequest.getCode();

        VerificationCode verificationCode = verificationCodeRepository
                .findFirstByCodeAndUsedFalseAndCancelledFalseOrderByCreatedAtDesc(code)
                .orElseThrow(InvalidOrUsedVerificationCodeException::new);

        if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ExpiredVerificationCodeException();
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


    public String randomSixDigit() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000)); // 000000 ile 999999 arasında 6 hane
    }


}
