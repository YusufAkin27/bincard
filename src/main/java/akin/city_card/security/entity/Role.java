package akin.city_card.security.entity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public enum Role implements GrantedAuthority {
    SUPERADMIN("SUPERADMIN"),
    USER("USER"),
    DRIVER("DRIVER"),
    MODERATOR("MODERATOR"),
    AUTO_TOP_UP_ADMIN("AUTO_TOP_UP_ADMIN"),
    BUS_ADMIN("BUS_ADMIN"),
    BUS_CARD_ADMIN("BUS_CARD_ADMIN"),
    CARD_VISA_ADMIN("CARD_VISA_ADMIN"),
    CONTRACT_ADMIN("CONTRACT_ADMIN"),
    DRIVER_ADMIN("DRIVER_ADMIN"),
    FEED_BACK_ADMIN("FEED_BACK_ADMIN"),
    GEO_ALERT_ADMIN("GEO_ALERT_ADMIN"),
    HEALTH_ADMIN("HEALTH_ADMIN"),
    PAYMENT_POINT_ADMIN("PAYMENT_POINT_ADMIN"),
    LOCATION_ADMIN("LOCATION_ADMIN"),
    NEWS_ADMIN("NEWS_ADMIN"),
    REPORT_ADMIN("REPORT_ADMIN"),
    NOTIFICATION_ADMIN("NOTIFICATION_ADMIN"),
    SCHEDULE_ADMIN("SCHEDULE_ADMIN"),
    ROUTE_ADMIN("ROUTE_ADMIN"),
    STATION_ADMIN("STATION_ADMIN"),
    USER_ADMIN("USER_ADMIN"),
    WALLET_ADMIN("WALLET_ADMIN"),
    ADMIN_ALL("ADMIN_ALL"),
    ROLE_EMPTY("ROLE_EMPTY");


    private final String role;

    @Override
    public String getAuthority() {
        return role;
    }
}
