package akin.city_card.route.model;

import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Embeddable
@Data
@AllArgsConstructor
@NoArgsConstructor
public class RouteSchedule {

    @ElementCollection
    @Enumerated(EnumType.STRING)
    private List<TimeSlot> weekdayHours;

    @ElementCollection
    @Enumerated(EnumType.STRING)
    private List<TimeSlot> weekendHours;

}
