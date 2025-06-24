package akin.city_card.user.controller;

import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotActiveException;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.exceptions.*;
import akin.city_card.user.service.abstracts.UserService;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import akin.city_card.verification.exceptions.InvalidOrUsedVerificationCodeException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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

    // 1. Kullanıcı kayıt
    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateUserRequest createUserRequest) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException {
        return userService.create(createUserRequest);
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
    public UUID verifyResetCode(@RequestBody VerificationCodeRequest verificationCodeRequest)
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
    public List<ResponseMessage> collectiveSignUp(@Valid @RequestBody CreateUserRequestList createUserRequestList) throws PhoneNumberRequiredException, InvalidPhoneNumberFormatException, PhoneNumberAlreadyExistsException {
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
}


