package akin.city_card.user.core.response;

import akin.city_card.user.model.SearchType;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class SearchHistoryDTO {

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private Long id;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private Long userId;

    @JsonView({Views.Public.class})
    private String query;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private boolean active;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private LocalDateTime searchedAt;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private SearchType searchType;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private boolean deleted;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private LocalDateTime deletedAt;

    @JsonView({Views.Admin.class, Views.SuperAdmin.class})
    private LocalDateTime createdAt;

}
