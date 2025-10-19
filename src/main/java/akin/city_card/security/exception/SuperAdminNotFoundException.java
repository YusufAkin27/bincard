package akin.city_card.security.exception;

public class SuperAdminNotFoundException extends BusinessException {
    public SuperAdminNotFoundException() {
        super("SuperAdmin bulunamadı");
    }
}
