package akin.city_card.buscard.core.request;

import lombok.Data;

@Data
public class FavoriteCardRequest {

    private String cardNumber;     // Favoriye alınacak kartın ID'si
    private String nickname;    // Kullanıcının vereceği takma isim

}
