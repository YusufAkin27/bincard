package akin.city_card.geoAlert.model;

public enum GeoAlertPriority {
    LOW("Düşük"),
    NORMAL("Normal"),
    HIGH("Yüksek"),
    URGENT("Acil");

    private final String displayName;

    GeoAlertPriority(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}