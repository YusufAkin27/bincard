package akin.city_card.security.manager;




import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.LoginRequestDTO;
import akin.city_card.security.dto.TokenResponseDTO;
import akin.city_card.security.dto.UpdateAccessTokenRequestDTO;
import akin.city_card.security.exception.*;
import org.springframework.http.ResponseEntity;

public interface AuthService {


    TokenResponseDTO login(LoginRequestDTO loginRequestDTO) throws NotFoundUserException, IncorrectPasswordException, UserDeletedException, UserNotActiveException, UserRoleNotAssignedException, PhoneNotVerifiedException, UnrecognizedDeviceException;

    ResponseEntity<?> updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) throws TokenIsExpiredException, TokenNotFoundException;

    ResponseMessage logout(String username) throws UserNotFoundException;
}
