package akin.city_card.admin.controller;

import akin.city_card.admin.core.request.CreateAdminRequest;
import akin.city_card.admin.repository.AdminRepository;
import akin.city_card.admin.service.abstracts.AdminService;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.exception.UserNotFoundException;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.request.VerificationCodeRequest;
import akin.city_card.user.exceptions.InvalidPhoneNumberFormatException;
import akin.city_card.user.exceptions.PhoneNumberAlreadyExistsException;
import akin.city_card.user.exceptions.PhoneNumberRequiredException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/api/admin")
@RequiredArgsConstructor
public class AdminController {

    public final AdminService adminService;
    // localhost:8008/v1/api/admin/sign-up
    // 1. Kullanıcı kayıt
    @PostMapping("/sign-up")
    public ResponseMessage signUp(@Valid @RequestBody CreateAdminRequest adminRequest) throws PhoneNumberRequiredException, PhoneNumberAlreadyExistsException, InvalidPhoneNumberFormatException {
        return adminService.signUp(adminRequest);
    }

}
