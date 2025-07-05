package akin.city_card.buscard.core.request;

import lombok.AllArgsConstructor;
import lombok.Data;


import lombok.Data;

@Data
public class FavoriteCardRequest {

    private Long busCardId;     // Favoriye alınacak kartın ID'si
    private String nickname;    // Kullanıcının vereceği takma isim

}
