package akin.city_card.bus.repository;

import akin.city_card.bus.model.BusRide;
import akin.city_card.bus.model.RideStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface BusRideRepository extends JpaRepository<BusRide, Long> {
    List<BusRide> findByBoardingTimeBetweenAndDriverUserNumber(LocalDateTime start, LocalDateTime end, String username);

    List<BusRide> findByBoardingTimeBetweenAndDriverUserNumberAndStatus(LocalDateTime start, LocalDateTime end, String username, RideStatus rideStatus);

    List<BusRide> findByDriverUserNumberAndStatus(String username, RideStatus rideStatus);

    List<BusRide> findByDriverIdAndBoardingTimeBetweenAndStatus(Long driverId, LocalDateTime start, LocalDateTime end, RideStatus rideStatus);
}
