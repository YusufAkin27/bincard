package akin.city_card.news.core.response;

import akin.city_card.user.core.response.Views;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonView;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.Page;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.ALWAYS)
public class PageDTO<T> {
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonView(Views.Public.class)
    private List<T> content;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonView(Views.Public.class)
    private int pageNumber;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonView(Views.Public.class)
    private int pageSize;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonView(Views.Public.class)
    private long totalElements;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonView(Views.Public.class)
    private int totalPages;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonView(Views.Public.class)
    private boolean first;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonView(Views.Public.class)
    private boolean last;

    public PageDTO(Page<T> page) {
        if (page == null) {
            this.content = new ArrayList<>();
            this.pageNumber = 0;
            this.pageSize = 0;
            this.totalElements = 0;
            this.totalPages = 0;
            this.first = true;
            this.last = true;
        } else {
            this.content = page.getContent() != null ? page.getContent() : new ArrayList<>();
            this.pageNumber = page.getNumber();
            this.pageSize = page.getSize();
            this.totalElements = page.getTotalElements();
            this.totalPages = page.getTotalPages();
            this.first = page.isFirst();
            this.last = page.isLast();
        }
    }


}