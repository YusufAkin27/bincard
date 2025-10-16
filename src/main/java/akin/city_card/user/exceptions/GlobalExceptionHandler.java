package akin.city_card.user.exceptions;

import akin.city_card.response.ResponseMessage;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.hibernate.PropertyValueException;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationErrors(
            MethodArgumentNotValidException ex) {

        BindingResult bindingResult = ex.getBindingResult();

        Map<String, String> errors = new HashMap<>();
        List<String> globalErrors = bindingResult.getGlobalErrors()
                .stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .collect(Collectors.toList());

        for (FieldError error : bindingResult.getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        ValidationErrorResponse errorResponse = new ValidationErrorResponse();
        errorResponse.setSuccess(false);
        errorResponse.setMessage("Girilen bilgilerde hatalar bulundu");
        errorResponse.setFieldErrors(errors);
        errorResponse.setGlobalErrors(globalErrors);

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ValidationErrorResponse> handleConstraintViolationException(
            ConstraintViolationException ex) {

        Map<String, String> errors = new HashMap<>();

        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            String fieldName = violation.getPropertyPath().toString();
            String errorMessage = violation.getMessage();
            errors.put(fieldName, errorMessage);
        }

        ValidationErrorResponse errorResponse = new ValidationErrorResponse();
        errorResponse.setSuccess(false);
        errorResponse.setMessage("Girilen bilgilerde hatalar bulundu");
        errorResponse.setFieldErrors(errors);
        errorResponse.setGlobalErrors(List.of());

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(PropertyValueException.class)
    public ResponseEntity<ValidationErrorResponse> handlePropertyValueException(
            PropertyValueException ex) {

        Map<String, String> errors = new HashMap<>();
        String fieldName = ex.getPropertyName();
        String userFriendlyMessage = getUserFriendlyMessage(fieldName, "required");

        errors.put(fieldName, userFriendlyMessage);

        ValidationErrorResponse errorResponse = new ValidationErrorResponse();
        errorResponse.setSuccess(false);
        errorResponse.setMessage("Zorunlu alanlar eksik");
        errorResponse.setFieldErrors(errors);
        errorResponse.setGlobalErrors(List.of());

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ValidationErrorResponse> handleDataIntegrityViolationException(
            DataIntegrityViolationException ex) {

        Map<String, String> errors = new HashMap<>();
        String message = ex.getMessage();

        // Constraint violation mesajlarını analiz et
        if (message != null) {
            if (message.contains("email") || message.contains("EMAIL")) {
                errors.put("email", "Bu email adresi zaten kullanılıyor");
            } else if (message.contains("phone") || message.contains("PHONE") || message.contains("userNumber")) {
                errors.put("phoneNumber", "Bu telefon numarası zaten kullanılıyor");
            } else if (message.contains("national") || message.contains("NATIONAL") || message.contains("nationalId")) {
                errors.put("nationalId", "Bu TC kimlik numarası zaten kullanılıyor");
            } else {
                errors.put("general", "Bu bilgi zaten sistemde kayıtlı");
            }
        }

        ValidationErrorResponse errorResponse = new ValidationErrorResponse();
        errorResponse.setSuccess(false);
        errorResponse.setMessage("Kayıt sırasında hata oluştu");
        errorResponse.setFieldErrors(errors);
        errorResponse.setGlobalErrors(List.of());

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ResponseMessage> handleHttpMessageNotReadableException(
            HttpMessageNotReadableException ex) {

        ResponseMessage errorResponse = new ResponseMessage();
        errorResponse.setSuccess(false);

        String message = ex.getMessage();
        if (message != null && message.contains("JSON")) {
            errorResponse.setMessage("Gönderilen veri formatı hatalı");
        } else if (message != null && message.contains("LocalDate")) {
            errorResponse.setMessage("Tarih formatı hatalı (yyyy-MM-dd formatında olmalı)");
        } else {
            errorResponse.setMessage("Gönderilen veri okunamıyor");
        }

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ResponseMessage> handleIllegalArgumentException(
            IllegalArgumentException ex) {

        ResponseMessage errorResponse = new ResponseMessage();
        errorResponse.setSuccess(false);
        errorResponse.setMessage("Geçersiz parametre değeri");

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<ResponseMessage> handleNullPointerException(
            NullPointerException ex) {

        ResponseMessage errorResponse = new ResponseMessage();
        errorResponse.setSuccess(false);
        errorResponse.setMessage("Zorunlu alan eksik");

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseMessage> handleGenericException(Exception ex) {
        ResponseMessage errorResponse = new ResponseMessage();
        errorResponse.setSuccess(false);
        errorResponse.setMessage("İşlem sırasında bir hata oluştu. Lütfen tekrar deneyin.");

        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // Alan adlarını kullanıcı dostu mesajlara çeviren yardımcı method
    private String getUserFriendlyMessage(String fieldName, String errorType) {
        Map<String, String> fieldMessages = Map.of(
                "userNumber", "Telefon numarası",
                "email", "Email adresi",
                "nationalId", "TC Kimlik numarası",
                "firstName", "Ad",
                "lastName", "Soyad",
                "birthDate", "Doğum tarihi",
                "password", "Şifre"
        );

        String friendlyFieldName = fieldMessages.getOrDefault(fieldName, fieldName);

        return switch (errorType) {
            case "required" -> friendlyFieldName + " alanı zorunludur";
            case "invalid" -> friendlyFieldName + " geçersiz formatta";
            case "exists" -> friendlyFieldName + " zaten kullanılıyor";
            default -> friendlyFieldName + " hatası";
        };
    }
}