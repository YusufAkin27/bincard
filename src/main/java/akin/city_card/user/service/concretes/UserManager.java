package akin.city_card.user.service.concretes;

import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.mail.MailService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.sms.SmsRequest;
import akin.city_card.sms.SmsService;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import akin.city_card.user.rules.UserRules;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.verification.model.VerificationChannel;
import akin.city_card.verification.model.VerificationCode;
import akin.city_card.verification.model.VerificationPurpose;
import akin.city_card.verification.repository.VerificationCodeRepository;
import akin.city_card.wallet.model.Currency;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.model.WalletStatus;
import akin.city_card.wallet.repository.WalletRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.beans.Transient;
import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
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


    @Override
    @Transactional
    public ResponseMessage create(CreateUserRequest request)
            throws PhoneNumberRequiredException,
            PhoneNumberAlreadyExistsException,
            InvalidPhoneNumberFormatException {

        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(request.getTelephone());
        request.setTelephone(normalizedPhone); // Güncellenmiş haliyle devam et

        userRules.checkPhoneIsUnique(request.getTelephone());

        // 2. Kullanıcıyı isteğe göre oluştur (userConverter üzerinden)
        User user = userConverter.convertUserToCreateUser(request);

        // 3. Veritabanına kaydet
        userRepository.save(user);

        // 4. Doğrulama kodu oluştur
        String code = randomSixDigit();

        // 5. SMS gönderimi
        SmsRequest smsRequest = new SmsRequest();
        smsRequest.setTo(request.getTelephone());
        smsRequest.setMessage("City Card - Doğrulama kodunuz: " + code +
                ". Kod 3 dakika boyunca geçerlidir.");
        smsService.sendSms(smsRequest);

        // 6. Doğrulama kodu bilgisi oluştur ve kaydet
        VerificationCode verificationCode = new VerificationCode();
        verificationCode.setCode(code);
        verificationCode.setCreatedAt(LocalDateTime.now());
        verificationCode.setUser(user);
        verificationCode.setChannel(VerificationChannel.SMS);
        verificationCode.setAttemptCount(0);
        verificationCode.setExpiresAt(LocalDateTime.now().plusMinutes(3));
        verificationCode.setCancelled(false);
        verificationCode.setPurpose(VerificationPurpose.REGISTER);
        verificationCode.setUsed(false);
        verificationCode.setIpAddress(request.getIpAddress());
        verificationCode.setUserAgent(request.getUserAgent());
        user.getVerificationCodes().add(verificationCode);

        verificationCodeRepository.save(verificationCode);

        // 7. Geri dönüş
        return new ResponseMessage("Kullanıcı başarıyla oluşturuldu. Doğrulama kodu SMS olarak gönderildi.", true);
    }

    @Override
    @Transactional
    public ResponseMessage verifyPhone(VerificationCodeRequest request) throws UserNotFoundException {
        VerificationCode verificationCode = verificationCodeRepository
                .findTopByCodeAndCancelledFalseAndUsedFalseOrderByCreatedAtDesc(request.getCode());

        if (verificationCode == null) {
            return new ResponseMessage("Geçersiz veya kullanılmamış doğrulama kodu bulunamadı.", false);
        }

        // Süresi dolmuşsa
        if (verificationCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            verificationCode.setCancelled(true);
            verificationCodeRepository.save(verificationCode);
            return new ResponseMessage("Doğrulama kodunun süresi dolmuş.", false);
        }

        // Çok fazla deneme yapılmışsa
        if (verificationCode.getAttemptCount() >= 3) {
            verificationCode.setCancelled(true);
            verificationCodeRepository.save(verificationCode);
            return new ResponseMessage("Bu doğrulama kodu çok fazla yanlış deneme nedeniyle iptal edildi.", false);
        }

        // Kod uyuşmuyorsa
        if (!verificationCode.getCode().equals(request.getCode())) {
            verificationCode.setAttemptCount(verificationCode.getAttemptCount() + 1);
            verificationCodeRepository.save(verificationCode);
            return new ResponseMessage("Doğrulama kodu hatalı.", false);
        }

        // Başarılı doğrulama
        User user = verificationCode.getUser();
        if (user == null) {
            throw new UserNotFoundException();
        }

        user.setPhoneVerified(true);
        user.setActive(true);
        userRepository.save(user);

        verificationCode.setUsed(true);
        verificationCode.setUserAgent(request.getUserAgent());
        verificationCode.setIpAddress(request.getIpAddress());
        verificationCodeRepository.save(verificationCode);

        return new ResponseMessage("Telefon numarası başarıyla doğrulandı.", true);
    }




    @Override
    public UserDTO getProfile(String username) throws UserNotFoundException {
        return userConverter.convertUserToDTO(userRepository.findByUserNumber(username));
    }

    @Override
    @Transactional
    public ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest) throws UserNotFoundException {
        // 1. Kullanıcıyı bul
        User user = userRepository.findByUserNumber(username);

        boolean isUpdated = false;

        // 2. Ad kontrolü ve güncellemesi
        if (updateProfileRequest.getName() != null &&
                !updateProfileRequest.getName().equals(user.getName())) {
            user.setName(updateProfileRequest.getName());
            isUpdated = true;
        }

        // 3. Soyad kontrolü ve güncellemesi
        if (updateProfileRequest.getSurname() != null &&
                !updateProfileRequest.getSurname().equals(user.getSurname())) {
            user.setSurname(updateProfileRequest.getSurname());
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
        return new ResponseMessage("Kullanıcı hesabı silindi.", true);
    }

    @Override
    public List<ResponseMessage> createAll(List<CreateUserRequest> createUserRequests) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException {
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

        // 1. Kullanıcıyı bul
        User user = userRepository.findByUserNumber(username);

        try {
            // 2. Fotoğrafı yükle ve optimize et (asenkron)
            CompletableFuture<String> futureUrl = mediaUploadService.uploadAndOptimizeImage(file);
            String imageUrl = futureUrl.get(); // blocking get

            // 3. Kullanıcıya ata
            user.setProfilePicture(imageUrl);

            // 4. Güncelle
            userRepository.save(user);

            return new ResponseMessage("Profil fotoğrafı başarıyla güncellendi.", true);

        } catch (InterruptedException | ExecutionException e) {
            Thread.currentThread().interrupt(); // thread flag'i temizle
            throw new IOException("Fotoğraf yüklenirken bir hata oluştu.", e);
        }
    }


    @Override
    public ResponseMessage sendEmailVerificationLink(String username) {
        return null;
    }

    @Override
    public ResponseMessage verifyEmail(String token) {
        return null;
    }

    @Override
    public ResponseMessage sendPasswordResetCode(String emailOrPhone) {
        return null;
    }

    @Override
    public ResponseMessage resetPassword(PasswordResetRequest request) {
        return null;
    }

    @Override
    public ResponseMessage changePassword(String username, ChangePasswordRequest request) {
        return null;
    }

    @Override
    public ResponseMessage enableTwoFactor(String username) {
        return null;
    }

    @Override
    public ResponseMessage disableTwoFactor(String username) {
        return null;
    }

    @Override
    public ResponseMessage resendPhoneVerificationCode(ResendPhoneVerificationRequest resendPhoneVerification) throws UserNotFoundException {
        String normalizedPhone = PhoneNumberFormatter.normalizeTurkishPhoneNumber(resendPhoneVerification.getTelephone());
        resendPhoneVerification.setTelephone(normalizedPhone); // Güncellenmiş haliyle devam et

        User user = userRepository.findByUserNumber(resendPhoneVerification.getTelephone());
        if (user == null) {
            throw new UserNotFoundException();
        }

        String code = randomSixDigit();

        // SMS gönderimi
        SmsRequest smsRequest = new SmsRequest();
        smsRequest.setTo(resendPhoneVerification.getTelephone());
        smsRequest.setMessage("City Card - Doğrulama kodunuz: " + code +
                ". Kod 3 dakika boyunca geçerlidir.");
        smsService.sendSms(smsRequest);

        // Doğrulama kodu bilgisi oluştur ve kaydet
        VerificationCode verificationCode = new VerificationCode();
        verificationCode.setCode(code);
        verificationCode.setCreatedAt(LocalDateTime.now());
        verificationCode.setUser(user);
        verificationCode.setChannel(VerificationChannel.SMS);
        verificationCode.setAttemptCount(0);
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

    public String randomSixDigit() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000)); // 000000 ile 999999 arasında 6 hane
    }

    @Override
    public ResponseMessage resendEmailVerificationLink(String email) {
        return null;
    }

}
