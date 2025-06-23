package akin.city_card.user.controller;

import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import akin.city_card.user.exceptions.PhotoSizeLargerException;
import akin.city_card.user.service.abstracts.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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

    // 1. Kullanıcı kayıt
    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateUserRequest createUserRequest) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException {
        return userService.create(createUserRequest);
    }
    //sms doğrulama
    @PostMapping("/verify/phone")
    public ResponseMessage verifyPhone(@RequestBody VerificationCodeRequest verificationCodeRequest) throws UserNotFoundException {
        return userService.verifyPhone( verificationCodeRequest);
    }
    @PostMapping("/verify/email/send")
    public ResponseMessage sendEmailVerification(@AuthenticationPrincipal UserDetails userDetails) {
        return userService.sendEmailVerificationLink(userDetails.getUsername());
    }
    @GetMapping("/verify/email")
    public ResponseMessage verifyEmail(@RequestParam("token") String token) {
        return userService.verifyEmail(token);
    }
    @PostMapping("/password/forgot")
    public ResponseMessage sendResetCode(@RequestParam("emailOrPhone") String emailOrPhone) {
        return userService.sendPasswordResetCode(emailOrPhone);
    }
    @PostMapping("/password/reset")
    public ResponseMessage resetPassword(@RequestBody PasswordResetRequest request) {
        return userService.resetPassword(request);
    }
    @PutMapping("/password/change")
    public ResponseMessage changePassword(@AuthenticationPrincipal UserDetails userDetails,
                                          @RequestBody ChangePasswordRequest request) {
        return userService.changePassword(userDetails.getUsername(), request);
    }
    // Telefon için yeniden doğrulama kodu gönderme
    @PostMapping("/verify/phone/resend")
    public ResponseMessage resendPhoneVerification(@RequestBody ResendPhoneVerificationRequest request) throws UserNotFoundException {
        return userService.resendPhoneVerificationCode(request);
    }

    // Email için yeniden doğrulama linki gönderme
    @PostMapping("/verify/email/resend")
    public ResponseMessage resendEmailVerification(@RequestParam String email) {
        return userService.resendEmailVerificationLink(email);
    }
    @PostMapping("/2fa/enable")
    public ResponseMessage enable2FA(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.enableTwoFactor(userDetails.getUsername());
    }
    @DeleteMapping("/2fa/disable")
    public ResponseMessage disable2FA(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.disableTwoFactor(userDetails.getUsername());
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
                                              @RequestParam("photo") MultipartFile file) throws UserNotFoundException, PhotoSizeLargerException, IOException {
        return userService.updateProfilePhoto(userDetails.getUsername(), file);
    }

    // 5. Hesap pasifleştirme (soft delete gibi)
    @DeleteMapping("/deactivate")
    public ResponseMessage deactivateUser(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
        return userService.deactivateUser(userDetails.getUsername());
    }
}


