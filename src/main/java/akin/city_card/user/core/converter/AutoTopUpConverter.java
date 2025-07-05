package akin.city_card.user.core.converter;

import akin.city_card.user.core.response.AutoTopUpConfigDTO;
import akin.city_card.user.model.AutoTopUpConfig;

public interface AutoTopUpConverter {
    AutoTopUpConfigDTO convertToDTO(AutoTopUpConfig config);
}
