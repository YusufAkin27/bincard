package akin.city_card.security.manager;




import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.admin.exceptions.AdminNotFoundException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.exception.*;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import org.springframework.http.ResponseEntity;

public interface AuthService {


    TokenResponseDTO login(LoginRequestDTO loginRequestDTO) throws NotFoundUserException, IncorrectPasswordException, UserDeletedException, UserNotActiveException, UserRoleNotAssignedException, PhoneNotVerifiedException, UnrecognizedDeviceException, AdminNotApprovedException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;

    TokenDTO updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) throws TokenIsExpiredException, TokenNotFoundException, UserNotFoundException, InvalidRefreshTokenException;

    ResponseMessage logout(String username) throws UserNotFoundException, TokenNotFoundException;

    TokenResponseDTO phoneVerify(LoginPhoneVerifyCodeRequest phoneVerifyCode) throws ExpiredVerificationCodeException, InvalidVerificationCodeException, UsedVerificationCodeException, CancelledVerificationCodeException;

    ResponseMessage adminLogin(LoginRequestDTO loginRequestDTO) throws NotFoundUserException, IncorrectPasswordException, UserRoleNotAssignedException, UserDeletedException, AdminNotApprovedException, UserNotActiveException, AdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;

    ResponseMessage superadminLogin(LoginRequestDTO loginRequestDTO) throws IncorrectPasswordException, UserRoleNotAssignedException, UserNotActiveException, UserDeletedException, SuperAdminNotFoundException, UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;

    TokenDTO refreshLogin(RefreshLoginRequest request) throws TokenIsExpiredException, TokenNotFoundException, InvalidRefreshTokenException, UserNotFoundException, IncorrectPasswordException;

    ResponseMessage resendVerifyCode(String telephone) throws UserNotFoundException, VerificationCodeStillValidException, VerificationCooldownException;
}
