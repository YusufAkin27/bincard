package akin.city_card.user.exceptions;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class ValidationErrorResponse {
    private boolean success;
    private String message;
    private Map<String, String> fieldErrors;
    private List<String> globalErrors;

}