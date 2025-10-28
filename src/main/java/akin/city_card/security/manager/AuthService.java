package akin.city_card.security.manager;


import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.bus.exceptions.DriverNotFoundException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.entity.Role;
import akin.city_card.security.exception.*;
import akin.city_card.user.core.request.UnfreezeAccountRequest;
import akin.city_card.user.exceptions.AccountNotFrozenException;
import akin.city_card.verification.exceptions.VerificationCodeExpiredException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Set;

public interface AuthService {


    TokenResponseDTO login(LoginRequestDTO loginRequestDTO, HttpServletRequest request) throws NotFoundUserException, IncorrectPasswordException, UserDeletedException, UserNotActiveException, UserRoleNotAssignedException, PhoneNotVerifiedException, UnrecognizedDeviceException, AdminNotApprovedException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException, AccountFrozenException;

    TokenDTO updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO, HttpServletRequest httpServletRequest) throws TokenIsExpiredException, TokenNotFoundException, UserNotFoundException, InvalidRefreshTokenException;

    ResponseMessage logout(String username, HttpServletRequest httpServletRequest) throws UserNotFoundException, TokenNotFoundException;

    TokenResponseDTO phoneVerify(LoginPhoneVerifyCodeRequest phoneVerifyCode, HttpServletRequest httpServletRequest) throws VerificationCodeExpiredException, InvalidVerificationCodeException, UsedVerificationCodeException, CancelledVerificationCodeException;

    ResponseMessage adminLogin(LoginRequestDTO loginRequestDTO, HttpServletRequest request) throws NotFoundUserException, IncorrectPasswordException, UserRoleNotAssignedException, UserDeletedException, AdminNotApprovedException, UserNotActiveException, AdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException, AccountFrozenException;

    ResponseMessage superadminLogin(HttpServletRequest request, LoginRequestDTO loginRequestDTO) throws IncorrectPasswordException, UserRoleNotAssignedException, UserNotActiveException, UserDeletedException, SuperAdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException, AccountFrozenException;

    TokenDTO refreshLogin(HttpServletRequest request, RefreshLoginRequest refreshRequest) throws TokenIsExpiredException, TokenNotFoundException, InvalidRefreshTokenException, UserNotFoundException, IncorrectPasswordException;

    ResponseMessage resendVerifyCode(String telephone, HttpServletRequest httpServletRequest) throws UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;


    ResponseMessage unfreezeAccount(UnfreezeAccountRequest request, HttpServletRequest httpRequest) throws AccountNotFrozenException, UserNotFoundException, IncorrectPasswordException;

    TokenResponseDTO driverLogin(HttpServletRequest request, String cardUid) throws DriverNotFoundException, IncorrectPasswordException, AccountFrozenException, PhoneNotVerifiedException, UnrecognizedDeviceException;

    Set<Role> getRoles(UserDetails userDetails) throws UserNotFoundException;
}
