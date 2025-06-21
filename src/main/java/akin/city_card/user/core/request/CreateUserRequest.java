package akin.city_card.user.core.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateUserRequest {
    @NotNull(message = "isim boş olamaz")
    private String firstName;
    @NotNull(message = "soyisim boş olamaz")
    private String lastName;
    private String telephone;
    private String password;
    // Kimlik numarası (isteğe bağlı)
    private String nationalId;

    // Doğum tarihi (isteğe bağlı)
    private LocalDate birthDate;
}
