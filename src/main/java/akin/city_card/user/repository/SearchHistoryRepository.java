package akin.city_card.user.repository;

import akin.city_card.user.model.SearchHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface SearchHistoryRepository extends JpaRepository<SearchHistory, Long> {
    @Query("""
                SELECT sh FROM SearchHistory sh
                WHERE sh.user.id = :userId
                AND (:startDate IS NULL OR sh.searchedAt >= :startDate)
                AND (:endDate IS NULL OR sh.searchedAt <= :endDate)
                ORDER BY sh.searchedAt DESC
            """)
    Page<SearchHistory> findByUserIdAndDateRange(
            @Param("userId") Long userId,
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate,
            Pageable pageable
    );
}
