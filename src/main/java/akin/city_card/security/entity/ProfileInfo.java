package akin.city_card.security.entity;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProfileInfo {
    private String name;
    private String surname;
    private String email;
    private String profilePicture;
}
