package akin.city_card.user.core.converter;

import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.UserExportDTO;
import akin.city_card.user.model.User;

public interface UserConverter {

    User convertUserToCreateUser(CreateUserRequest createUserRequest);
    UserExportDTO convertUserToExportDTO(User user);
    CacheUserDTO toCacheUserDTO(User user);

}
