package akin.city_card.user.core.converter;

import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.AutoTopUpConfigDTO;
import akin.city_card.user.core.response.UserDTO;
import akin.city_card.user.core.response.UserExportDTO;
import akin.city_card.user.model.AutoTopUpConfig;
import akin.city_card.user.model.User;

public interface UserConverter {

    User convertUserToCreateUser(CreateUserRequest createUserRequest);
    UserDTO convertUserToDTO(User user);
    UserExportDTO convertUserToExportDTO(User user);
}
