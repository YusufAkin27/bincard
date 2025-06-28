package akin.city_card.security.manager;




import akin.city_card.admin.exceptions.AdminNotApprovedException;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.*;
import akin.city_card.security.exception.*;
import akin.city_card.verification.exceptions.ExpiredVerificationCodeException;
import org.springframework.http.ResponseEntity;

public interface AuthService {


    TokenResponseDTO login(LoginRequestDTO loginRequestDTO) throws NotFoundUserException, IncorrectPasswordException, UserDeletedException, UserNotActiveException, UserRoleNotAssignedException, PhoneNotVerifiedException, UnrecognizedDeviceException, AdminNotApprovedException;

    TokenDTO updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) throws TokenIsExpiredException, TokenNotFoundException, UserNotFoundException, InvalidRefreshTokenException;

    ResponseMessage logout(String username) throws UserNotFoundException, TokenNotFoundException;

    TokenResponseDTO phoneVerify(LoginPhoneVerifyCodeRequest phoneVerifyCode) throws ExpiredVerificationCodeException;
}
