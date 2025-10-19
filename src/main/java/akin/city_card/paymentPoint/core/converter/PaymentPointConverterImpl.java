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
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class PaymentPointConverterImpl implements PaymentPointConverter {

    @Override
    public PaymentPoint toEntity(AddPaymentPointRequest request) {
        PaymentPoint paymentPoint = new PaymentPoint();

        paymentPoint.setName(request.getName());
        paymentPoint.setLocation(toLocationEntity(request.getLocation()));
        paymentPoint.setAddress(toAddressEntity(request.getAddress()));
        paymentPoint.setContactNumber(request.getContactNumber());
        paymentPoint.setWorkingHours(request.getWorkingHours());
        paymentPoint.setPaymentMethods(request.getPaymentMethods());
        paymentPoint.setDescription(request.getDescription());
        paymentPoint.setActive(request.isActive());

        return paymentPoint;
    }

    @Override
    public PaymentPointDTO toDto(PaymentPoint paymentPoint) {
        PaymentPointDTO dto = new PaymentPointDTO();

        dto.setId(paymentPoint.getId());
        dto.setName(paymentPoint.getName());
        dto.setLocation(toLocationDto(paymentPoint.getLocation()));
        dto.setAddress(toAddressDto(paymentPoint.getAddress()));
        dto.setContactNumber(paymentPoint.getContactNumber());
        dto.setWorkingHours(paymentPoint.getWorkingHours());
        dto.setPaymentMethods(paymentPoint.getPaymentMethods());
        dto.setDescription(paymentPoint.getDescription());
        dto.setActive(paymentPoint.isActive());
        dto.setCreatedAt(paymentPoint.getCreatedAt());
        dto.setLastUpdated(paymentPoint.getLastUpdated());

        if (paymentPoint.getPhotos() != null) {
            dto.setPhotos(paymentPoint.getPhotos().stream()
                    .map(this::toPaymentPhotoDto)
                    .collect(Collectors.toList()));
        }

        return dto;
    }

    @Override
    public void updateEntity(PaymentPoint paymentPoint, UpdatePaymentPointRequest request) {
        paymentPoint.setName(request.getName());

        if (request.getLocation() != null) {
            paymentPoint.setLocation(toLocationEntity(request.getLocation()));
        }

        if (request.getAddress() != null) {
            paymentPoint.setAddress(toAddressEntity(request.getAddress()));
        }

        paymentPoint.setContactNumber(request.getContactNumber());
        paymentPoint.setWorkingHours(request.getWorkingHours());
        paymentPoint.setPaymentMethods(request.getPaymentMethods());
        paymentPoint.setDescription(request.getDescription());
        paymentPoint.setActive(request.isActive());
    }

    @Override
    public Location toLocationEntity(LocationDTO locationDTO) {
        Location location = new Location();
        location.setLatitude(locationDTO.getLatitude());
        location.setLongitude(locationDTO.getLongitude());
        return location;
    }

    @Override
    public LocationDTO toLocationDto(Location location) {
        return LocationDTO.builder()
                .latitude(location.getLatitude())
                .longitude(location.getLongitude())
                .build();
    }

    @Override
    public Address toAddressEntity(AddressDTO addressDTO) {
        Address address = new Address();
        address.setStreet(addressDTO.getStreet());
        address.setDistrict(addressDTO.getDistrict());
        address.setCity(addressDTO.getCity());
        address.setPostalCode(addressDTO.getPostalCode());
        return address;
    }

    @Override
    public AddressDTO toAddressDto(Address address) {
        AddressDTO dto = new AddressDTO();
        dto.setStreet(address.getStreet());
        dto.setDistrict(address.getDistrict());
        dto.setCity(address.getCity());
        dto.setPostalCode(address.getPostalCode());
        return dto;
    }

    @Override
    public PaymentPhotoDTO toPaymentPhotoDto(PaymentPhoto photo) {
        PaymentPhotoDTO dto = new PaymentPhotoDTO();
        dto.setId(photo.getId());
        dto.setImageUrl(photo.getImageUrl());
        return dto;
    }
}
