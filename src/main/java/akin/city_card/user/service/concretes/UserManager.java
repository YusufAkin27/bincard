package akin.city_card.user.service.concretes;

import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.admin.model.AuditLog;
import akin.city_card.admin.repository.AuditLogRepository;
import akin.city_card.buscard.core.converter.BusCardConverter;
import akin.city_card.buscard.core.request.FavoriteCardRequest;
import akin.city_card.buscard.core.response.FavoriteBusCardDTO;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.UserFavoriteCard;
import akin.city_card.buscard.repository.BusCardRepository;
import akin.city_card.cloudinary.MediaUploadService;
import akin.city_card.mail.EmailMessage;
import akin.city_card.mail.MailService;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.notification.core.request.NotificationPreferencesDTO;
import akin.city_card.notification.model.NotificationPreferences;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotActiveException;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.exception.VerificationCodeStillValidException;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.sms.SmsService;
import akin.city_card.user.core.converter.AutoTopUpConverter;
import akin.city_card.user.core.converter.UserConverter;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.AutoTopUpConfigDTO;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.core.response.UserExportDTO;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.model.AutoTopUpConfig;
import akin.city_card.user.model.PasswordResetToken;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.AutoTopUpConfigRepository;
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
import akin.city_card.wallet.core.converter.WalletConverter;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.exceptions.WalletIsEmptyException;
import akin.city_card.wallet.model.Wallet;
import akin.city_card.wallet.repository.WalletRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
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
    private final BusCardConverter busCardConverter;
    private final BusCardRepository busCardRepository;
    private final WalletRepository walletRepository;
    private final WalletConverter walletConverter;
    private final AutoTopUpConfigRepository autoTopUpConfigRepository;
    private final AutoTopUpConverter autoTopUpConverter;
    private AuditLogRepository auditLogRepository;

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

    @Override
    public boolean updateFCMToken(String fcmToken, String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        user.getDeviceInfo().setFcmToken(fcmToken);
        return true;
    }

    @Override
    public Page<UserDTO> getAllUsers(String username, int page, int size)
            throws UserNotActiveException, UnauthorizedAreaException {

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotActiveException::new);

        if (securityUser.getRoles() == null ||
                securityUser.getRoles().stream().noneMatch(role ->
                        role.name().equals("ADMIN") || role.name().equals("SUPERADMIN"))) {
            throw new UnauthorizedAreaException();
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<User> userPage = userRepository.findAll(pageable);

        return userPage.map(userConverter::convertUserToDTO);
    }


    @Override
    public Page<UserDTO> searchUser(String username, String query, int page, int size)
            throws UserNotActiveException, UnauthorizedAreaException, UserNotFoundException {

        SecurityUser securityUser = securityUserRepository.findByUserNumber(username)
                .orElseThrow(UserNotActiveException::new);

        if (securityUser.getRoles() == null ||
                securityUser.getRoles().stream().noneMatch(role ->
                        role.name().equals("ADMIN") || role.name().equals("SUPERADMIN"))) {
            throw new UnauthorizedAreaException();
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());

        Page<User> results = userRepository.searchByQuery(query.toLowerCase(), pageable);

        if (results.isEmpty()) {
            throw new UserNotFoundException();
        }

        return results.map(userConverter::convertUserToDTO);
    }

    @Override
    public List<FavoriteBusCardDTO> getFavoriteCards(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);
        List<UserFavoriteCard> busCards = user.getFavoriteCards();
        return busCards.stream().map(busCardConverter::favoriteBusCardToDTO).toList();

    }

    @Override
    public ResponseMessage addFavoriteCard(String username, FavoriteCardRequest request) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);

        BusCard busCard = busCardRepository.findById(request.getBusCardId())
                .orElseThrow(() -> new RuntimeException("BusCard bulunamadı"));

        boolean alreadyFavorited = user.getFavoriteCards().stream()
                .anyMatch(fav -> fav.getBusCard().getId().equals(busCard.getId()));
        if (alreadyFavorited) {
            return new ResponseMessage("Bu kart zaten favorilerde.", false);
        }

        UserFavoriteCard favorite = new UserFavoriteCard();
        favorite.setUser(user);
        favorite.setBusCard(busCard);
        favorite.setNickname(request.getNickname());

        user.getFavoriteCards().add(favorite);
        userRepository.save(user);

        return new ResponseMessage("Kart favorilere başarıyla eklendi.", true);
    }

    @Override
    public ResponseMessage removeFavoriteCard(String username, Long cardId) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);

        List<UserFavoriteCard> favoriteCards = user.getFavoriteCards();
        boolean isSuccess = favoriteCards.removeIf(fav ->
                fav.getBusCard() != null && fav.getBusCard().getId().equals(cardId)
        );

        if (isSuccess) {
            userRepository.save(user);
        }

        return new ResponseMessage("Favoriden silme işlemi " + (isSuccess ? "başarılı" : "başarısız"), isSuccess);
    }

    @Override
    public WalletDTO getWallet(String username) throws WalletIsEmptyException, UserNotFoundException {
        User user = userRepository.findByUserNumber(username);

        Wallet wallet = user.getWallet();
        if (wallet == null) {
            throw new WalletIsEmptyException();
        }
        return walletConverter.convertToDTO(wallet);
    }

    @Override
    public ResponseMessage updateNotificationPreferences(String username, NotificationPreferencesDTO preferencesDto) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);


        NotificationPreferences preferences = user.getNotificationPreferences();

        if (preferences == null) {
            preferences = new NotificationPreferences();
        }
        if (preferencesDto.getNotifyBeforeMinutes() != null && preferencesDto.getNotifyBeforeMinutes() < 0) {
            return new ResponseMessage("Bildirim süresi negatif olamaz", false);
        }

        preferences.setPushEnabled(preferencesDto.isPushEnabled());
        preferences.setSmsEnabled(preferencesDto.isSmsEnabled());
        preferences.setEmailEnabled(preferencesDto.isEmailEnabled());
        preferences.setNotifyBeforeMinutes(preferencesDto.getNotifyBeforeMinutes());
        preferences.setFcmActive(preferencesDto.isFcmActive());

        user.setNotificationPreferences(preferences);
        userRepository.save(user);

        return new ResponseMessage("Bildirim tercihleri güncellendi", true);
    }

    @Override
    public List<AutoTopUpConfigDTO> getAutoTopUpConfigs(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);


        List<AutoTopUpConfig> configs = autoTopUpConfigRepository.findByUser(user);

        return configs.stream()
                .map(autoTopUpConverter::convertToDTO)
                .toList();
    }

    @Override
    public UserExportDTO exportUserData(String username) throws UserNotFoundException {
        User user = userRepository.findByUserNumber(username);

        UserExportDTO dto = userConverter.convertUserToExportDTO(user);

        String emailBody = buildEmailBodyFromDTO(dto);

        EmailMessage emailMessage = new EmailMessage();
        emailMessage.setToEmail(user.getProfileInfo().getEmail()); // Email varsa
        emailMessage.setSubject("Hesap Bilgileriniz");
        emailMessage.setBody(emailBody);
        emailMessage.setHtml(false);

        mailService.queueEmail(emailMessage);

        return dto;
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

    private String buildEmailBodyFromDTO(UserExportDTO dto) {
        StringBuilder sb = new StringBuilder();

        sb.append("Sayın ").append(dto.getFullName() != null ? dto.getFullName() : "Kullanıcı").append(",\n\n");
        sb.append("City Card hesabınıza ait bilgiler aşağıda yer almaktadır:\n\n");

        sb.append("──────────────────────────────\n");
        sb.append("Kullanıcı ID      : ").append(dto.getId()).append("\n");
        sb.append("Kullanıcı No      : ").append(dto.getUserNumber() != null ? dto.getUserNumber() : "—").append("\n");
        sb.append("TC Kimlik No      : ").append(dto.getNationalId() != null ? dto.getNationalId() : "—").append("\n");
        sb.append("Doğum Tarihi      : ").append(dto.getBirthDate() != null ? dto.getBirthDate() : "—").append("\n");
        sb.append("Cüzdan Aktif      : ").append(dto.isWalletActivated() ? "Evet" : "Hayır").append("\n");
        sb.append("Negatif Bakiye İzin: ").append(dto.isAllowNegativeBalance() ? "Evet" : "Hayır").append("\n");
        sb.append("Negatif Bakiye Limit: ").append(dto.getNegativeBalanceLimit() != null ? dto.getNegativeBalanceLimit() : "0.0").append("\n");
        sb.append("Otomatik Yükleme   : ").append(dto.isAutoTopUpEnabled() ? "Aktif" : "Pasif").append("\n");
        sb.append("Hesap Oluşturulma : ").append(dto.getCreatedAt() != null ? dto.getCreatedAt() : "—").append("\n");
        sb.append("Son Güncelleme    : ").append(dto.getUpdatedAt() != null ? dto.getUpdatedAt() : "—").append("\n");
        sb.append("──────────────────────────────\n\n");

        sb.append("Herhangi bir sorunuz için bizimle iletişime geçebilirsiniz.\n");
        sb.append("City Card Ekibi olarak sizi aramızda görmekten mutluluk duyuyoruz.\n\n");
        sb.append("İyi günler dileriz.");

        return sb.toString();
    }


    public String randomSixDigit() {
        Random random = new Random();
        return String.format("%06d", random.nextInt(1000000)); // 000000 ile 999999 arasında 6 hane
    }


}
