package akin.city_card.user.core.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeleteAccountRequest {
    @NotBlank(message = "Şifre boş olamaz")
    private String password;

    @NotBlank(message = "Silme nedeni belirtilmelidir")
    @Size(max = 500, message = "Silme nedeni 500 karakteri geçemez")
    private String reason;

    @AssertTrue(message = "Hesap silme işlemini onaylamalısınız")
    private boolean confirmDeletion;
}
