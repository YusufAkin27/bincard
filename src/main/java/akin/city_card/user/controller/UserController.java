package akin.city_card.user.controller;

import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.admin.core.response.AuditLogDTO;
import akin.city_card.buscard.core.request.FavoriteCardRequest;
import akin.city_card.buscard.core.response.FavoriteBusCardDTO;
import akin.city_card.buscard.exceptions.BusCardNotFoundException;
import akin.city_card.notification.core.request.NotificationPreferencesDTO;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.*;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.core.response.Views;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.verification.exceptions.*;
import com.fasterxml.jackson.annotation.JsonView;
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

@RestController
@RequestMapping("/v1/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateUserRequest createUserRequest, HttpServletRequest request) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException, VerificationCodeStillValidException {
        return userService.create(createUserRequest, request);
    }

    @PostMapping("/verify/phone")
    public ResponseMessage verifyPhone(@Valid @RequestBody VerificationCodeRequest verificationCodeRequest, HttpServletRequest request) throws UserNotFoundException, CancelledVerificationCodeException, VerificationCodeNotFoundException, UsedVerificationCodeException, VerificationCodeExpiredException {
        return userService.verifyPhone(verificationCodeRequest, request);
    }

    // 📲 Adım 1: Şifremi unuttum -> Telefon numarasına kod gönder
    @PostMapping("/password/forgot")
    public ResponseMessage sendResetCode(@RequestParam("phone") String phone, HttpServletRequest httpServletRequest) throws UserNotFoundException {
        return userService.sendPasswordResetCode(phone, httpServletRequest);
    }

    @PostMapping("/password/verify-code")
    public ResponseMessage verifyResetCode(@Valid @RequestBody VerificationCodeRequest verificationCodeRequest)
            throws VerificationCodeExpiredException, InvalidOrUsedVerificationCodeException {
        return userService.verifyPhoneForPasswordReset(verificationCodeRequest);
    }

    @PostMapping("/password/reset")
    public ResponseMessage resetPassword(@RequestBody PasswordResetRequest request, HttpServletRequest httpServletRequest) throws SamePasswordException, PasswordTooShortException, PasswordResetTokenNotFoundException, PasswordResetTokenExpiredException, PasswordResetTokenIsUsedException {
        return userService.resetPassword(request, httpServletRequest);
    }

    @PutMapping("/password/change")
    public ResponseMessage changePassword(@AuthenticationPrincipal UserDetails userDetails,
                                          @RequestBody ChangePasswordRequest request,
                                          HttpServletRequest httpServletRequest) throws UserNotFoundException, PasswordsDoNotMatchException, IncorrectCurrentPasswordException, UserNotActiveException, InvalidNewPasswordException, SamePasswordException, UserIsDeletedException {
        return userService.changePassword(userDetails.getUsername(), request, httpServletRequest);
    }

    // Telefon için yeniden doğrulama kodu gönderme
    @PostMapping("/verify/phone/resend")
    public ResponseMessage resendPhoneVerification(@RequestBody ResendPhoneVerificationRequest request, HttpServletRequest httpServletRequest) throws UserNotFoundException {
        return userService.resendPhoneVerificationCode(request);
    }


    // 2. Profil görüntüleme
    @GetMapping("/profile")
    @JsonView(Views.User.class)
    public CacheUserDTO getProfile(@AuthenticationPrincipal UserDetails userDetails, HttpServletRequest httpServletRequest) throws UserNotFoundException {
        return userService.getProfile(userDetails.getUsername(), httpServletRequest);
    }

    // 3. Profil güncelleme
    @PutMapping("/profile")
    public ResponseMessage updateProfile(@AuthenticationPrincipal UserDetails userDetails,
                                         @RequestBody UpdateProfileRequest updateProfileRequest,
                                         HttpServletRequest httpServletRequest) throws UserNotFoundException, EmailAlreadyExistsException {
        return userService.updateProfile(userDetails.getUsername(), updateProfileRequest, httpServletRequest);
    }

    @PostMapping("/email-verify/{token}")
    public ResponseMessage verifyEmail(
            @PathVariable("token") String token,
            @RequestParam("email") String email,
            HttpServletRequest request
    ) throws UserNotFoundException, VerificationCodeStillValidException, VerificationCodeNotFoundException, VerificationCodeExpiredException, VerificationCodeAlreadyUsedException, EmailMismatchException, VerificationCodeTypeMismatchException, VerificationCodeCancelledException, InvalidVerificationCodeException {
        return userService.verifyEmail(token, email, request);
    }


    //profil fotoğrafı yükleme
    @PutMapping("/profile/photo")
    public ResponseMessage uploadProfilePhoto(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestParam("photo") MultipartFile file,
                                              HttpServletRequest httpServletRequest) throws UserNotFoundException, PhotoSizeLargerException, IOException {
        return userService.updateProfilePhoto(userDetails.getUsername(), file, httpServletRequest);
    }

    @DeleteMapping("/profile/photo")
    public ResponseMessage deleteProfilePhoto(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, PhotoSizeLargerException, IOException {
        return userService.deleteProfilePhoto(userDetails.getUsername());
    }

    // Hesap silme işlemi (kalıcı silme)
    @DeleteMapping("/delete-account")
    public ResponseMessage deleteAccount(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody DeleteAccountRequest request,
            HttpServletRequest httpRequest
    ) throws UserNotFoundException, IncorrectPasswordException, UserNotActiveException, PasswordsDoNotMatchException, ApproveIsConfirmDeletionException, WalletBalanceNotZeroException {
        return userService.deleteAccount(userDetails.getUsername(), request, httpRequest);
    }


    @PostMapping("/freeze-account")
    public ResponseMessage freezeAccount(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestBody FreezeAccountRequest request,
            HttpServletRequest httpRequest
    ) throws UserNotFoundException {
        return userService.freezeAccount(userDetails.getUsername(), request, httpRequest);
    }


    @PatchMapping("/update-fcm-token")
    public boolean updateFCMToken(@RequestParam String fcmToken, @AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.updateFCMToken(fcmToken, userDetails.getUsername());
    }

    // FAVORİ KARTLAR
    @GetMapping("/favorites/cards")
    public List<FavoriteBusCardDTO> getFavoriteCards(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.getFavoriteCards(userDetails.getUsername());
    }

    @PostMapping("/favorites/cards")
    public ResponseMessage addFavoriteCard(@AuthenticationPrincipal UserDetails userDetails,
                                           @RequestBody FavoriteCardRequest request) throws UserNotFoundException, BusCardNotFoundException {
        return userService.addFavoriteCard(userDetails.getUsername(), request);
    }

    @DeleteMapping("/favorites/cards/{cardId}")
    public ResponseMessage removeFavoriteCard(@AuthenticationPrincipal UserDetails userDetails,
                                              @PathVariable String cardNumber) throws UserNotFoundException {
        return userService.removeFavoriteCard(userDetails.getUsername(), cardNumber);
    }

    @PostMapping("/location")
    public void updateLocation(@AuthenticationPrincipal UserDetails userDetails,
                               @RequestBody @Valid UpdateLocationRequest updateLocationRequest) throws UserNotFoundException {
        userService.updateLocation(userDetails.getUsername(), updateLocationRequest);
    }


    // BİLDİRİM TERCİHLERİ
    @PutMapping("/notification-preferences")
    public CacheUserDTO updateNotificationPreferences(@AuthenticationPrincipal UserDetails userDetails,
                                                      @RequestBody NotificationPreferencesDTO preferences) throws UserNotFoundException {
        return userService.updateNotificationPreferences(userDetails.getUsername(), preferences);
    }


    // DÜŞÜK BAKİYE UYARISI
    @PutMapping("/balance-alert")
    public ResponseMessage setLowBalanceAlert(@AuthenticationPrincipal UserDetails userDetails,
                                              @RequestBody LowBalanceAlertRequest request) throws UserNotFoundException, BusCardNotFoundException, AlreadyBusCardLowBalanceException {
        return userService.setLowBalanceThreshold(userDetails.getUsername(), request);
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


    @GetMapping("/activity-log")
    public Page<AuditLogDTO> getUserActivityLog(
            @AuthenticationPrincipal UserDetails userDetails,
            @PageableDefault(size = 10, sort = "timestamp", direction = Sort.Direction.DESC) Pageable pageable
    ) throws UserNotFoundException {
        return userService.getUserActivityLog(userDetails.getUsername(), pageable);
    }


}


