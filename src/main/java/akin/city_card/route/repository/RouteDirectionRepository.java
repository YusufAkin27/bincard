package akin.city_card.route.repository;

import akin.city_card.route.model.RouteDirection;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RouteDirectionRepository extends JpaRepository<RouteDirection, Long> {
}
