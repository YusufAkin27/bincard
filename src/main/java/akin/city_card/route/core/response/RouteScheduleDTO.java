package akin.city_card.route.core.response;

import akin.city_card.route.model.TimeSlot;
import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RouteScheduleDTO {

    @JsonView(Views.User.class)
    private List<TimeSlot> weekdayHours;

    @JsonView(Views.User.class)
    private List<TimeSlot> weekendHours;
}
