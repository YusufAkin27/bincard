package akin.city_card.buscard.core.converter;

import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.core.response.FavoriteBusCardDTO;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.CardPricing;
import akin.city_card.buscard.model.UserFavoriteCard;
import org.springframework.stereotype.Component;

@Component
public class BusCardConverterImpl implements BusCardConverter {

    @Override
    public BusCardDTO BusCardToBusCardDTO(BusCard busCard) {
        if (busCard == null) {
            return null;
        }

        BusCardDTO dto = new BusCardDTO();
        dto.setId(busCard.getId());
        dto.setCardNumber(busCard.getCardNumber());
        dto.setFullName(busCard.getFullName());
        dto.setType(busCard.getType());
        dto.setBalance(busCard.getBalance());
        dto.setStatus(busCard.getStatus());
        dto.setActive(busCard.isActive());
        dto.setIssueDate(busCard.getIssueDate());
        dto.setExpiryDate(busCard.getExpiryDate());

        return dto;
    }

    @Override
    public FavoriteBusCardDTO favoriteBusCardToDTO(UserFavoriteCard favorite) {
        if (favorite == null || favorite.getBusCard() == null) {
            return null;
        }

        FavoriteBusCardDTO dto = new FavoriteBusCardDTO();

        BusCard busCard = favorite.getBusCard();

        dto.setId(busCard.getId());
        dto.setCardNumber(busCard.getCardNumber());
        dto.setFullName(busCard.getFullName());
        dto.setType(busCard.getType());
        dto.setBalance(busCard.getBalance());
        dto.setStatus(busCard.getStatus());
        dto.setActive(busCard.isActive());
        dto.setIssueDate(busCard.getIssueDate());
        dto.setExpiryDate(busCard.getExpiryDate());

        dto.setNickname(favorite.getNickname());

        return dto;
    }

    @Override
    public CardPricingDTO cardPricingToDTO(CardPricing cardPricing) {
        CardPricingDTO dto = new CardPricingDTO();
        dto.setCardType(cardPricing.getCardType());
        dto.setPrice(cardPricing.getPrice());
        return dto;
    }

}
