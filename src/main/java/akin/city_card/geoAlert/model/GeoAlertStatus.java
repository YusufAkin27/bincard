package akin.city_card.geoAlert.model;

public enum GeoAlertStatus {
    ACTIVE("Aktif"),           // Uyarı aktif, araç bekleniyor
    COMPLETED("Tamamlandı"),   // Uyarı tetiklendi ve bildirim gönderildi
    CANCELLED("İptal Edildi"), // Kullanıcı tarafından iptal edildi
    EXPIRED("Süresi Doldu");   // Belirli bir süre sonra otomatik iptal (opsiyonel)

    private final String displayName;

    GeoAlertStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isActive() {
        return this == ACTIVE;
    }

    public boolean isFinished() {
        return this == COMPLETED || this == CANCELLED || this == EXPIRED;
    }
}