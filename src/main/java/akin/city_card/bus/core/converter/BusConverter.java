package akin.city_card.bus.core.converter;


import akin.city_card.admin.core.request.UpdateLocationRequest;
import akin.city_card.bus.core.request.CreateBusRequest;
import akin.city_card.bus.core.request.UpdateBusRequest;
import akin.city_card.bus.core.response.BusDTO;
import akin.city_card.bus.core.response.BusLocationDTO;
import akin.city_card.bus.core.response.BusRideDTO;
import akin.city_card.bus.model.Bus;
import akin.city_card.bus.model.BusLocation;
import akin.city_card.bus.model.BusRide;
import akin.city_card.news.core.response.PageDTO;
import org.springframework.data.domain.Page;

import java.util.List;

public interface BusConverter {

    BusDTO toBusDTO(Bus bus);

    List<BusDTO> toBusDTOList(List<Bus> buses);

    Bus fromCreateBusRequest(CreateBusRequest request);

    void updateBusFromRequest(Bus bus, UpdateBusRequest request);

    BusLocationDTO toBusLocationDTO(BusLocation location);

    List<BusLocationDTO> toBusLocationDTOList(List<BusLocation> locations);

    BusLocation fromUpdateLocationRequest(UpdateLocationRequest request);

    BusRideDTO toBusRideDTO(BusRide ride);

    List<BusRideDTO> toBusRideDTOList(List<BusRide> rides);

    PageDTO<BusDTO> toPageDTO(Page<Bus> busPage);

    PageDTO<BusLocationDTO> toLocationPageDTO(Page<BusLocation> page);
}
