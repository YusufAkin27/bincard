package akin.city_card.security.manager;




import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.exception.*;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;

public interface AuthService {


    TokenResponseDTO login(LoginRequestDTO loginRequestDTO, HttpServletRequest request) throws NotFoundUserException, IncorrectPasswordException, UserDeletedException, UserNotActiveException, UserRoleNotAssignedException, PhoneNotVerifiedException, UnrecognizedDeviceException, AdminNotApprovedException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;

    TokenDTO updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO,HttpServletRequest httpServletRequest) throws TokenIsExpiredException, TokenNotFoundException, UserNotFoundException, InvalidRefreshTokenException;

    ResponseMessage logout(String username) throws UserNotFoundException, TokenNotFoundException;

    TokenResponseDTO phoneVerify(LoginPhoneVerifyCodeRequest phoneVerifyCode,HttpServletRequest httpServletRequest) throws ExpiredVerificationCodeException, InvalidVerificationCodeException, UsedVerificationCodeException, CancelledVerificationCodeException;

    ResponseMessage adminLogin(LoginRequestDTO loginRequestDTO, HttpServletRequest request) throws NotFoundUserException, IncorrectPasswordException, UserRoleNotAssignedException, UserDeletedException, AdminNotApprovedException, UserNotActiveException, AdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;

    ResponseMessage superadminLogin(HttpServletRequest request, LoginRequestDTO loginRequestDTO) throws IncorrectPasswordException, UserRoleNotAssignedException, UserNotActiveException, UserDeletedException, SuperAdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;

    TokenDTO refreshLogin(HttpServletRequest request, RefreshLoginRequest refreshRequest) throws TokenIsExpiredException, TokenNotFoundException, InvalidRefreshTokenException, UserNotFoundException, IncorrectPasswordException;

    ResponseMessage resendVerifyCode(String telephone) throws UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;
}
