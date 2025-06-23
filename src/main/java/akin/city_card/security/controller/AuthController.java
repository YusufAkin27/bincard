package akin.city_card.security.controller;



import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.LoginRequestDTO;
import akin.city_card.security.dto.TokenResponseDTO;
import akin.city_card.security.dto.UpdateAccessTokenRequestDTO;
import akin.city_card.security.exception.*;
import akin.city_card.security.manager.AuthService;
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
    public TokenResponseDTO login(@RequestBody LoginRequestDTO loginRequestDTO) throws UserNotActiveException, UserRoleNotAssignedException, UserDeletedException, NotFoundUserException, IncorrectPasswordException, UnrecognizedDeviceException, PhoneNotVerifiedException {
        return authService.login(loginRequestDTO);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> updateAccessToken(@RequestBody UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) throws TokenIsExpiredException, TokenNotFoundException {
        return authService.updateAccessToken(updateAccessTokenRequestDTO);
    }

    @PostMapping("logout")
    public ResponseMessage logout(@AuthenticationPrincipal UserDetails userDetails) throws UserNotFoundException {
      return authService.logout(userDetails.getUsername());
    }

}
