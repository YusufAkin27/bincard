package akin.city_card.buscard.model;

import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AbonmanKart extends BusCard {

    private LocalDate subscriptionStartDate;
    private LocalDate subscriptionEndDate;
    private Double monthlyFee;
    private Integer maxMonthlyUsages;

    private boolean isStudentSubscription;

    @Embedded
    private StudentInfo studentInfo;
}
