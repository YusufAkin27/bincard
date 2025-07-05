package akin.city_card.user.controller;

import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.buscard.core.request.FavoriteCardRequest;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.FavoriteBusCardDTO;
import akin.city_card.news.exceptions.UnauthorizedAreaException;
import akin.city_card.notification.core.request.NotificationPreferencesDTO;
import akin.city_card.response.DataResponseMessage;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotActiveException;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.security.exception.VerificationCodeStillValidException;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.AutoTopUpConfigDTO;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.core.response.UserExportDTO;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import akin.city_card.verification.exceptions.InvalidOrUsedVerificationCodeException;
import akin.city_card.wallet.core.response.WalletDTO;
import akin.city_card.wallet.exceptions.WalletIsEmptyException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/v1/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateUserRequest createUserRequest, HttpServletRequest request) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException, VerificationCodeStillValidException {
        String ipAddress = extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        createUserRequest.setIpAddress(ipAddress);
        createUserRequest.setUserAgent(userAgent);

        return userService.create(createUserRequest);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }


    //sms doğrulama
    @PostMapping("/verify/phone")
    public ResponseMessage verifyPhone(@RequestBody VerificationCodeRequest verificationCodeRequest) throws UserNotFoundException {
        return userService.verifyPhone(verificationCodeRequest);
    }

    // 📲 Adım 1: Şifremi unuttum -> Telefon numarasına kod gönder
    @PostMapping("/password/forgot")
    public ResponseMessage sendResetCode(@RequestParam("phone") String phone) throws UserNotFoundException {
        return userService.sendPasswordResetCode(phone);
    }

    // ✅ Adım 2: Telefon numarasını doğrulama (kod girilerek)
    @PostMapping("/password/verify-code")
    public ResponseMessage verifyResetCode(@RequestBody VerificationCodeRequest verificationCodeRequest)
            throws UserNotFoundException, ExpiredVerificationCodeException, InvalidOrUsedVerificationCodeException {
        return userService.verifyPhoneForPasswordReset(verificationCodeRequest);
    }

    // 🔐 Adım 3: Yeni şifre belirleme
    @PostMapping("/password/reset")
    public ResponseMessage resetPassword(@RequestBody PasswordResetRequest request) throws SamePasswordException, PasswordTooShortException, PasswordResetTokenNotFoundException, PasswordResetTokenExpiredException, PasswordResetTokenIsUsedException {
        return userService.resetPassword(request);
    }

    @PutMapping("/password/change")
    public ResponseMessage changePassword(@AuthenticationPrincipal UserDetails userDetails,
                                          @RequestBody ChangePasswordRequest request) throws UserNotFoundException, PasswordsDoNotMatchException, IncorrectCurrentPasswordException, UserNotActiveException, InvalidNewPasswordException, SamePasswordException, UserIsDeletedException {
        return userService.changePassword(userDetails.getUsername(), request);
    }

    // Telefon için yeniden doğrulama kodu gönderme
    @PostMapping("/verify/phone/resend")
    public ResponseMessage resendPhoneVerification(@RequestBody ResendPhoneVerificationRequest request) throws UserNotFoundException {
        return userService.resendPhoneVerificationCode(request);
    }

    @PostMapping("/collective-sign-up")
    public List<ResponseMessage> collectiveSignUp(@Valid @RequestBody CreateUserRequestList createUserRequestList) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException, VerificationCodeStillValidException {
        return userService.createAll(createUserRequestList.getUsers());
    }

    // 2. Profil görüntüleme
    @GetMapping("/profile")
    public UserDTO getProfile(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.getProfile(userDetails.getUsername());
    }

    // 3. Profil güncelleme
    @PutMapping("/profile")
    public ResponseMessage updateProfile(@AuthenticationPrincipal UserDetails userDetails,
                                         @RequestBody UpdateProfileRequest updateProfileRequest) throws UserNotFoundException {
        return userService.updateProfile(userDetails.getUsername(), updateProfileRequest);
    }

    //profil fotoğrafı yükleme
    @PutMapping("/profile/photo")
    public ResponseMessage uploadProfilePhoto(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestParam("photo")
                                              MultipartFile file) throws UserNotFoundException, PhotoSizeLargerException, IOException {
        return userService.updateProfilePhoto(userDetails.getUsername(), file);
    }
    // 5. Hesap pasifleştirme (soft delete gibi)
    @DeleteMapping("/deactivate")
    public ResponseMessage deactivateUser(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.deactivateUser(userDetails.getUsername());
    }

    @PatchMapping("/update-fcm-token")
    public boolean updateFCMToken(@RequestParam String fcmToken,@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.updateFCMToken(fcmToken,userDetails.getUsername());
    }
    // Tüm kullanıcıları sayfalı listeleme
// Tüm kullanıcıları sayfalı listeleme
    @GetMapping("/admin/all")
    public Page<UserDTO> getAllUsers(@AuthenticationPrincipal UserDetails userDetails,
                                     @RequestParam(defaultValue = "0") int page,
                                     @RequestParam(defaultValue = "10") int size)
            throws UserNotActiveException, UnauthorizedAreaException {
        return userService.getAllUsers(userDetails.getUsername(), page, size);
    }

    // Tek sorgu ile kullanıcı arama (sayfalı)
    @GetMapping("/admin/search")
    public Page<UserDTO> searchUser(@RequestParam String query,
                                    @AuthenticationPrincipal UserDetails userDetails,
                                    @RequestParam(defaultValue = "0") int page,
                                    @RequestParam(defaultValue = "10") int size)
            throws UserNotFoundException, UnauthorizedAreaException, UserNotActiveException {
        return userService.searchUser(userDetails.getUsername(), query, page, size);
    }


    // FAVORİ KARTLAR
    @GetMapping("/favorites/cards")
    public List<FavoriteBusCardDTO> getFavoriteCards(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.getFavoriteCards(userDetails.getUsername());
    }

    @PostMapping("/favorites/cards")
    public ResponseMessage addFavoriteCard(@AuthenticationPrincipal UserDetails userDetails,
                                           @RequestBody FavoriteCardRequest request) throws UserNotFoundException {
        return userService.addFavoriteCard(userDetails.getUsername(), request);
    }

    @DeleteMapping("/favorites/cards/{cardId}")
    public ResponseMessage removeFavoriteCard(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable Long cardId) throws UserNotFoundException {
        return userService.removeFavoriteCard(userDetails.getUsername(), cardId);
    }

    // CÜZDAN
    @GetMapping("/wallet")
    public WalletDTO getWallet(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, WalletIsEmptyException {
        return userService.getWallet(userDetails.getUsername());
    }

    // BİLDİRİM TERCİHLERİ
    @PutMapping("/notification-preferences")
    public ResponseMessage updateNotificationPreferences(@AuthenticationPrincipal UserDetails userDetails,
                                                         @RequestBody NotificationPreferencesDTO preferences) throws UserNotFoundException {
        return userService.updateNotificationPreferences(userDetails.getUsername(), preferences);
    }

    // OTOMATİK YÜKLEME AYARLARI
    @GetMapping("/auto-top-up")
    public List<AutoTopUpConfigDTO> getAutoTopUpConfigs(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.getAutoTopUpConfigs(userDetails.getUsername());
    }
/*
    @PostMapping("/auto-top-up")
    public ResponseMessage addAutoTopUpConfig(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestBody AutoTopUpConfigRequest configRequest) throws UserNotFoundException {
        return userService.addAutoTopUpConfig(userDetails.getUsername(), configRequest);
    }

    @DeleteMapping("/auto-top-up/{configId}")
    public ResponseMessage deleteAutoTopUpConfig(@AuthenticationPrincipal UserDetails userDetails,
                                                 @PathVariable UUID configId) throws UserNotFoundException {
        return userService.deleteAutoTopUpConfig(userDetails.getUsername(), configId);
    }

    // DÜŞÜK BAKİYE UYARISI
    @PutMapping("/balance-alert")
    public ResponseMessage setLowBalanceAlert(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestBody LowBalanceAlertRequest request) throws UserNotFoundException {
        return userService.setLowBalanceThreshold(userDetails.getUsername(), request.getCardId(), request.getThreshold());
    }

    // ARAMA GEÇMİŞİ
    @GetMapping("/search-history")
    public List<SearchHistoryDTO> getSearchHistory(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.getSearchHistory(userDetails.getUsername());
    }

    @DeleteMapping("/search-history")
    public ResponseMessage clearSearchHistory(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.clearSearchHistory(userDetails.getUsername());
    }

    // KONUMA DAYALI UYARILAR
    @GetMapping("/geo-alerts")
    public List<GeoAlertDTO> getGeoAlerts(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.getGeoAlerts(userDetails.getUsername());
    }

    @PostMapping("/geo-alerts")
    public ResponseMessage addGeoAlert(@AuthenticationPrincipal UserDetails userDetails,
                                       @RequestBody GeoAlertRequest alertRequest) throws UserNotFoundException {
        return userService.addGeoAlert(userDetails.getUsername(), alertRequest);
    }

    @DeleteMapping("/geo-alerts/{alertId}")
    public ResponseMessage deleteGeoAlert(@AuthenticationPrincipal UserDetails userDetails,
                                          @PathVariable UUID alertId) throws UserNotFoundException {
        return userService.deleteGeoAlert(userDetails.getUsername(), alertId);
    }



    @GetMapping("/activity-log")
    public Page<AuditLogDTO> getUserActivityLog(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "timestamp", direction = Sort.Direction.DESC) Pageable pageable
    ) throws UserNotFoundException {
        return userService.getUserActivityLog(userDetails.getUsername(), pageable);
    }

 */
    @GetMapping("/export")
    public UserExportDTO exportUserData(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.exportUserData(userDetails.getUsername());
    }


}


