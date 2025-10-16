package akin.city_card.user.core.response;

public class Views {
    public interface Public {
    }

    public interface User extends Public {
    }

    public interface Admin extends User {
    }

    public interface SuperAdmin extends Admin {
    }

    public interface Private extends SuperAdmin {
    }
}
