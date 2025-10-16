package akin.city_card.paymentPoint.core.converter;

import akin.city_card.paymentPoint.core.request.AddPaymentPointRequest;
import akin.city_card.paymentPoint.core.request.UpdatePaymentPointRequest;
import akin.city_card.paymentPoint.core.response.AddressDTO;
import akin.city_card.paymentPoint.core.response.LocationDTO;
import akin.city_card.paymentPoint.core.response.PaymentPhotoDTO;
import akin.city_card.paymentPoint.core.response.PaymentPointDTO;
import akin.city_card.paymentPoint.model.Address;
import akin.city_card.paymentPoint.model.Location;
import akin.city_card.paymentPoint.model.PaymentPhoto;
import akin.city_card.paymentPoint.model.PaymentPoint;

public interface PaymentPointConverter {
    PaymentPhotoDTO toPaymentPhotoDto(PaymentPhoto photo);

    AddressDTO toAddressDto(Address address);

    Address toAddressEntity(AddressDTO addressDTO);

    LocationDTO toLocationDto(Location location);

    Location toLocationEntity(LocationDTO locationDTO);

    void updateEntity(PaymentPoint paymentPoint, UpdatePaymentPointRequest request);

    PaymentPointDTO toDto(PaymentPoint paymentPoint);

    PaymentPoint toEntity(AddPaymentPointRequest request);

}
