package akin.city_card.report.exceptions;

import akin.city_card.security.exception.BusinessException;

public class CategoryNotFoundExecption extends BusinessException {
    public CategoryNotFoundExecption() {
        super("Kategori bulunumadı");
    }
}
