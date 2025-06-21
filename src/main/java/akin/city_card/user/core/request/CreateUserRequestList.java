package akin.city_card.user.core.request;

import jakarta.validation.Valid;
import lombok.Data;

import java.util.List;

@Data
public class CreateUserRequestList {
    @Valid
    private List<CreateUserRequest> users;

}
