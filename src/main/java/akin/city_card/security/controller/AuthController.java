package akin.city_card.security.controller;


import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.exception.*;
import akin.city_card.security.manager.AuthService;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/v1/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/login")
    public TokenResponseDTO login(@RequestBody LoginRequestDTO loginRequestDTO) throws UserNotActiveException, UserRoleNotAssignedException, UserDeletedException, NotFoundUserException, IncorrectPasswordException, UnrecognizedDeviceException, PhoneNotVerifiedException, AdminNotApprovedException {
        return authService.login(loginRequestDTO);
    }

    @PostMapping("/phone-verify")
    public TokenResponseDTO phoneVerify(@RequestBody LoginPhoneVerifyCodeRequest phoneVerifyCode) throws ExpiredVerificationCodeException {
        return authService.phoneVerify(phoneVerifyCode);
    }

    @PostMapping("/refresh")
    public TokenDTO updateAccessToken(@RequestBody UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) throws TokenIsExpiredException, TokenNotFoundException, UserNotFoundException, InvalidRefreshTokenException {
        return authService.updateAccessToken(updateAccessTokenRequestDTO);
    }

    @PostMapping("logout")
    public ResponseMessage logout(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException, TokenNotFoundException {
        return authService.logout(userDetails.getUsername());
    }

}
