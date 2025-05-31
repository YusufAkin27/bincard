package akin.city_card.admin.model;

import akin.city_card.security.entity.SecurityUser;
import akin.city_card.user.model.User;
import jakarta.persistence.Entity;
import jakarta.persistence.*;

@Entity
public class Admin extends SecurityUser {


    @OneToOne
    private User user;

    private String position; // Örn: "Sistem Yöneticisi"
}
