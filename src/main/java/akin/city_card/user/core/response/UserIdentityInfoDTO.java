package akin.city_card.user.core.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Builder
public class UserIdentityInfoDTO {

    private Long id;

    private String frontCardPhoto;

    private String backCardPhoto;

    private String nationalId;

    private String serialNumber;

    private LocalDate birthDate;

    private String gender;

    private String motherName;

    private String fatherName;


    private String approvedByPhone;

    private Boolean approved;

    private LocalDateTime approvedAt;


    private String userPhone;
}
