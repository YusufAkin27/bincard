package akin.city_card.user.core.converter;

import akin.city_card.user.core.response.AutoTopUpConfigDTO;
import akin.city_card.user.model.AutoTopUpConfig;
import org.springframework.stereotype.Component;

@Component
public class AutoTopUpConverterImpl implements AutoTopUpConverter {
    @Override
    public AutoTopUpConfigDTO convertToDTO(AutoTopUpConfig config) {
        if (config == null) return null;

        AutoTopUpConfigDTO dto = new AutoTopUpConfigDTO();
        dto.setId(config.getId());
        dto.setUserId(config.getUser() != null ? config.getUser().getId() : null);
        dto.setBusCardId(config.getBusCard() != null ? config.getBusCard().getId() : null);
        dto.setWalletId(config.getWallet() != null ? config.getWallet().getId() : null);
        dto.setThreshold(config.getThreshold());
        dto.setAmount(config.getAmount());
        dto.setActive(config.isActive());
        dto.setLastTopUpAt(config.getLastTopUpAt());
        dto.setCreatedAt(config.getCreatedAt());

        return dto;
    }

}
