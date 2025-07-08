package akin.city_card.user.core.converter;

import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.*;
import akin.city_card.user.model.*;

public interface UserConverter {

    User convertUserToCreateUser(CreateUserRequest createUserRequest);

    CacheUserDTO toCacheUserDTO(User user);

    SearchHistoryDTO toSearchHistoryDTO(SearchHistory searchHistory);
    UserIdentityInfoDTO toUserIdentityInfoDTO(UserIdentityInfo entity);
    GeoAlertDTO toGeoAlertDTO(GeoAlert geoAlert);
    IdentityVerificationRequestDTO convertToVerificationRequestDTO(IdentityVerificationRequest entity);

}
