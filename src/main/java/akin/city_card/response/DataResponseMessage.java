package akin.city_card.response;


import lombok.Data;

@Data
public class DataResponseMessage<T> extends ResponseMessage {
    private T data;

    public DataResponseMessage(String message, boolean isSuccess, T data) {
        super(message, isSuccess);
        this.data = data;
    }

    public static <T> DataResponseMessage<T> of(T data) {
        return new DataResponseMessage<>("İşlem başarılı", true, data);
    }

}
