package akin.city_card.security.manager;


import akin.city_card.response.ResponseMessage;
import akin.city_card.security.dto.AccessTokenResponse;
import akin.city_card.security.dto.LoginRequestDTO;
import akin.city_card.security.dto.TokenResponseDTO;
import akin.city_card.security.dto.UpdateAccessTokenRequestDTO;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.*;
import akin.city_card.security.repository.SecurityUserRepository;
import akin.city_card.security.repository.TokenRepository;
import akin.city_card.security.service.JwtService;
import akin.city_card.user.model.User;
import akin.city_card.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthManager implements AuthService {
    private final SecurityUserRepository securityUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public ResponseMessage logout(String username) throws UserNotFoundException {
        User student = userRepository.findByUserNumber(username).orElseThrow(UserNotFoundException::new);
        tokenRepository.deleteAllBySecurityUser_Id(student.getId());


        return new ResponseMessage("Çıkış başarılı", true);
    }
    @Override
    public TokenResponseDTO login(LoginRequestDTO loginRequestDTO)
            throws NotFoundUserException, UserDeletedException, UserNotActiveException,
            IncorrectPasswordException, UserRoleNotAssignedException {

        SecurityUser user = securityUserRepository.findByUserNumber(loginRequestDTO.getTelephone())
                .orElseThrow(NotFoundUserException::new);

        if (user instanceof User u && !u.isActive()) {
            throw new UserNotActiveException();
        }

        if (!passwordEncoder.matches(loginRequestDTO.getPassword(), user.getPassword())) {
            throw new IncorrectPasswordException();
        }

        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            throw new UserRoleNotAssignedException();
        }

        String accessToken = jwtService.generateAccessToken(user, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());
        String refreshToken = jwtService.generateRefreshToken(user, loginRequestDTO.getIpAddress(), loginRequestDTO.getDeviceInfo());

        return new TokenResponseDTO(accessToken, refreshToken);
    }



    @Override
    public ResponseEntity<?> updateAccessToken(UpdateAccessTokenRequestDTO updateAccessTokenRequestDTO) {
        try {
            if (!jwtService.validateRefreshToken(updateAccessTokenRequestDTO.getRefreshToken())) {
                throw new InvalidRefreshTokenException();
            }

            String userNumber = jwtService.getRefreshTokenClaims(updateAccessTokenRequestDTO.getRefreshToken()).getSubject();
            User user = userRepository.findByUserNumber(userNumber)
                    .orElseThrow(UserNotFoundException::new);

            String ipAddress = updateAccessTokenRequestDTO.getIpAddress();
            String deviceInfo = updateAccessTokenRequestDTO.getDeviceInfo();
            String newAccessToken = jwtService.generateAccessToken(user, ipAddress, deviceInfo);

            return ResponseEntity.ok(new AccessTokenResponse(newAccessToken));
        } catch (TokenNotFoundException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token bulunamadı: " + e.getMessage());
        } catch (InvalidRefreshTokenException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Refresh token geçersiz: " + e.getMessage());
        } catch (UserNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Kullanıcı hatası: " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Bir hata meydana geldi: " + e.getMessage());
        }
    }




}
