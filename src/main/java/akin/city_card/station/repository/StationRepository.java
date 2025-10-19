package akin.city_card.station.repository;

import akin.city_card.station.model.Station;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface StationRepository extends JpaRepository<Station, Long> {


    List<Station> findAllByActiveTrue();


}
