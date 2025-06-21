package akin.city_card.user.service.abstracts;

import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.*;
import akin.city_card.user.core.response.UserDTO;
import jakarta.validation.Valid;

import java.util.List;

public interface UserService {

    ResponseMessage create(CreateUserRequest createUserRequest);

    UserDTO getProfile(String username);

    ResponseMessage updateProfile(String username, UpdateProfileRequest updateProfileRequest);

    ResponseMessage verifyPhone(String username, VerifyPhoneRequest request);

    ResponseMessage deactivateUser(String username);

    List<ResponseMessage> createAll(@Valid List<CreateUserRequest> createUserRequests);

}
