package akin.city_card.user.core.converter;

import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.model.User;

public interface UserConverter {

    User convertUserToCreateUser(CreateUserRequest createUserRequest);

}
