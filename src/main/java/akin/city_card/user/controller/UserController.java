package akin.city_card.user.controller;

import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.service.abstracts.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // 1. Kullanıcı kayıt
    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateUserRequest createUserRequest) {
        return userService.create(createUserRequest);
    }
    @PostMapping("/collective-sign-up")
    public List<ResponseMessage> collectiveSignUp(@Valid @RequestBody CreateUserRequestList createUserRequestList) {
        return userService.createAll(createUserRequestList.getUsers());
    }

    // 2. Profil görüntüleme
    @GetMapping("/profile")
    public UserDTO getProfile(@AuthenticationPrincipal UserDetails userDetails) {
        return userService.getProfile(userDetails.getUsername());
    }

    // 3. Profil güncelleme
    @PutMapping("/profile")
    public ResponseMessage updateProfile(@AuthenticationPrincipal UserDetails userDetails,
                                         @RequestBody UpdateProfileRequest updateProfileRequest) {
        return userService.updateProfile(userDetails.getUsername(), updateProfileRequest);
    }


    // 4. Telefon doğrulama sonucu güncelle
    @PostMapping("/verify-phone")
    public ResponseMessage verifyPhone(@AuthenticationPrincipal UserDetails userDetails,
                                       @RequestBody VerifyPhoneRequest request) {
        return userService.verifyPhone(userDetails.getUsername(), request);
    }

    // 5. Hesap pasifleştirme (soft delete gibi)
    @DeleteMapping("/deactivate")
    public ResponseMessage deactivateUser(@AuthenticationPrincipal UserDetails userDetails) {
        return userService.deactivateUser(userDetails.getUsername());
    }
}


