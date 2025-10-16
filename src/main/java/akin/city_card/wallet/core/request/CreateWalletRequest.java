package akin.city_card.wallet.core.request;

import akin.city_card.validations.Adult;
import akin.city_card.validations.ValidNationalId;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;

@Data
public class CreateWalletRequest {

    @NotBlank(message = "T.C. Kimlik numarası boş olamaz.")
    @ValidNationalId
    private String nationalId;

    @NotNull(message = "Doğum tarihi zorunludur.")
    @Adult
    private LocalDate birthDate;

    @NotBlank(message = "Cinsiyet boş olamaz.")
    @Pattern(regexp = "^(Erkek|Kadın)$", message = "Cinsiyet 'Erkek', 'Kadın' veya 'Diğer' olmalıdır.")
    private String gender;

    @NotBlank(message = "Anne adı boş olamaz.")
    private String motherName;

    @NotBlank(message = "Baba adı boş olamaz.")
    private String fatherName;

    @Size(min = 9, max = 9, message = "Seri numarası 9 karakter olmalıdır.")
    private String serialNumber;

    @NotNull(message = "Kimlik ön yüz fotoğrafı yüklenmelidir.")
    private MultipartFile frontCardPhoto;

    @NotNull(message = "Kimlik arka yüz fotoğrafı yüklenmelidir.")
    private MultipartFile backCardPhoto;
}

