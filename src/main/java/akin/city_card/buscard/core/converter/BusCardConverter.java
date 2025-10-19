package akin.city_card.buscard.core.converter;

import akin.city_card.buscard.core.request.RegisterCardRequest;
import akin.city_card.buscard.core.response.BusCardDTO;
import akin.city_card.buscard.core.response.CardPricingDTO;
import akin.city_card.buscard.core.response.FavoriteBusCardDTO;
import akin.city_card.buscard.model.BusCard;
import akin.city_card.buscard.model.CardPricing;
import akin.city_card.buscard.model.UserFavoriteCard;

public interface BusCardConverter {
    BusCardDTO BusCardToBusCardDTO(BusCard busCard);

    FavoriteBusCardDTO favoriteBusCardToDTO(UserFavoriteCard favorite);

    CardPricingDTO cardPricingToDTO(CardPricing cardPricing);

    BusCard registerCard(RegisterCardRequest req);
}
