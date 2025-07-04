package akin.city_card.response;


import lombok.Builder;
import lombok.Data;


public class DataResponseMessage<T> extends ResponseMessage {
    private T data;

    public DataResponseMessage(String message, boolean isSuccess, T data) {
        super(message, isSuccess);
        this.data = data;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
