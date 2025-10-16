package akin.city_card.news.repository;

import akin.city_card.news.model.News;
import akin.city_card.news.model.NewsType;
import akin.city_card.news.model.PlatformType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface NewsRepository extends JpaRepository<News, Long> {

    List<News> findByTypeAndActiveTrue(NewsType type);

    @Query("SELECT n FROM News n WHERE n.startDate <= :now AND n.active = false")
    List<News> findByStartDateBeforeAndActiveFalse(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM News n WHERE n.endDate <= :now AND n.active = true")
    List<News> findByEndDateBeforeAndActiveTrue(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM News n WHERE n.active = true AND " +
            "(n.startDate IS NULL OR n.startDate <= :now) AND " +
            "(n.endDate IS NULL OR n.endDate > :now)")
    List<News> findActiveNewsAtTime(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM News n WHERE n.startDate > :now")
    List<News> findScheduledNews(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM News n WHERE n.endDate < :now")
    List<News> findExpiredNews(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM News n WHERE n.startDate >= :start AND n.startDate <= :end")
    List<News> findNewsByDateRange(@Param("start") LocalDateTime start, @Param("end") LocalDateTime end);

    @Query("SELECT n FROM News n WHERE n.active = true AND " +
            "(n.startDate IS NULL OR n.startDate <= :now) AND " +
            "(n.endDate IS NULL OR n.endDate > :now) " +
            "ORDER BY n.viewCount DESC")
    List<News> findActiveNewsByViewCount(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM News n WHERE n.active = true AND " +
            "(n.startDate IS NULL OR n.startDate <= :now) AND " +
            "(n.endDate IS NULL OR n.endDate > :now) " +
            "ORDER BY n.priority DESC, n.createdAt DESC")
    List<News> findActiveNewsByPriority(@Param("now") LocalDateTime now);

    @Query("SELECT n FROM News n WHERE n.active = true AND " +
            "(n.startDate IS NULL OR n.startDate <= :now) AND " +
            "(n.endDate IS NULL OR n.endDate > :now) AND " +
            "(n.platform = :platform OR n.platform = 'ALL')")
    List<News> findActiveNewsByPlatform(@Param("now") LocalDateTime now, @Param("platform") String platform);

    @Query("SELECT n FROM News n WHERE n.active = true AND " +
            "(n.startDate IS NULL OR n.startDate <= :now) AND " +
            "(n.endDate IS NULL OR n.endDate > :now) AND " +
            "n.type = :type AND " +
            "(n.platform = :platform OR n.platform = 'ALL')")
    List<News> findActiveNewsByTypeAndPlatform(@Param("now") LocalDateTime now,
                                               @Param("type") NewsType type,
                                               @Param("platform") String platform);

    @Query("SELECT n FROM News n WHERE n.updatedAt >= :since ORDER BY n.updatedAt DESC")
    List<News> findNewsUpdatedSince(@Param("since") LocalDateTime since);

    Page<News> findByPlatform(PlatformType platform, Pageable pageable);

    @Query("""
                SELECT n FROM News n
                WHERE n.active = true
                AND n.platform IN :platforms
                AND (n.startDate IS NULL OR n.startDate <= :now)
                AND (n.endDate IS NULL OR n.endDate > :now)
            """)
    Page<News> findByPlatformInAndActiveTrueAndValidEndDate(
            @Param("platforms") List<PlatformType> platforms,
            @Param("now") LocalDateTime now,
            Pageable pageable
    );

}