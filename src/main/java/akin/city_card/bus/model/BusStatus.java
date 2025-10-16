package akin.city_card.bus.model;

/**
 * Otobüs durumları
 */
public enum BusStatus {
    CALISIYOR("Çalışıyor"),
    ARIZALI("Arızalı"),
    BAKIMDA("Bakımda"),
    SERVIS_DISI("Servis Dışı"),
    DURAKTA_BEKLIYOR("Durakta Bekliyor"),
    HAREKET_HALINDE("Hareket Halinde"),
    GARAJDA("Garajda"),
    TEMIZLIK("Temizlik"),
    YAKIT_ALIMI("Yakıt Alımı"),
    MOLA("Mola");

    private final String displayName;

    BusStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Otobüs yolcu alabilir mi?
     */
    public boolean canTakePassengers() {
        return this == CALISIYOR || this == DURAKTA_BEKLIYOR || this == HAREKET_HALINDE;
    }

    /**
     * Otobüs aktif durumda mı?
     */
    public boolean isOperational() {
        return this != SERVIS_DISI && this != ARIZALI && this != BAKIMDA && this != GARAJDA;
    }
}