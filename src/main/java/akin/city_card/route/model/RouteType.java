package akin.city_card.route.model;

/**
 * Rota türleri
 */
public enum RouteType {
    CITY_BUS("Şehir İçi Otobüs"),
    METRO("Metro"),
    METROBUS("Metrobüs"),
    TRAM("Tramvay"),
    FERRY("Vapur"),
    MINIBUS("Minibüs"),
    EXPRESS("Ekspres");

    private final String displayName;

    RouteType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}