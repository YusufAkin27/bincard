package akin.city_card.user.core.converter;

import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.core.response.CacheUserDTO;
import akin.city_card.user.core.response.GeoAlertDTO;
import akin.city_card.user.core.response.SearchHistoryDTO;
import akin.city_card.user.model.GeoAlert;
import akin.city_card.user.model.SearchHistory;
import akin.city_card.user.model.User;

public interface UserConverter {

    User convertUserToCreateUser(CreateUserRequest createUserRequest);

    CacheUserDTO toCacheUserDTO(User user);

    SearchHistoryDTO toSearchHistoryDTO(SearchHistory searchHistory);

    GeoAlertDTO toGeoAlertDTO(GeoAlert geoAlert);
}
