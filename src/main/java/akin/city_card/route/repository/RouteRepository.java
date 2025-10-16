package akin.city_card.route.repository;

import akin.city_card.route.model.Route;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface RouteRepository extends JpaRepository<Route, Long> {


    @Query("""
            SELECT DISTINCT r FROM Route r
            JOIN r.directions d
            JOIN d.stationNodes n
            JOIN Station s1 ON n.fromStation = s1
            JOIN Station s2 ON n.toStation = s2
            WHERE r.isActive = true AND r.isDeleted = false
              AND (
                LOWER(r.name) LIKE LOWER(CONCAT('%', :keyword, '%')) OR
                LOWER(s1.name) LIKE LOWER(CONCAT('%', :keyword, '%')) OR
                LOWER(s2.name) LIKE LOWER(CONCAT('%', :keyword, '%'))
            )
            """)
    List<Route> searchByKeyword(@Param("keyword") String keyword);

}
