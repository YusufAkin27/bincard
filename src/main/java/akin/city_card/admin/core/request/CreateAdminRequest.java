package akin.city_card.admin.core.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateAdminRequest {
    private String telephone;
    private String password;
    private String name;
    private String surname;
    private String email;
    private String ipAddress;
    private String deviceUuid;



    private String userAgent;
}
