       package akin.city_card.response;
       
       import lombok.AllArgsConstructor;
       import lombok.Data;
       
       @Data
       @AllArgsConstructor
       public class ResponseMessage {
              private String message;
              private boolean isSuccess;
       }
