package akin.city_card.contract.core.converter;


import akin.city_card.contract.core.response.AcceptedContractDTO;
import akin.city_card.contract.core.response.ContractDTO;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.model.Contract;
import akin.city_card.contract.model.UserContractAcceptance;

public interface ContractConverter {

    ContractDTO mapToContractDTO(Contract contract);

    UserContractDTO mapToUserContractDTO(Contract contract, UserContractAcceptance userContractAcceptance);

    AcceptedContractDTO mapToAcceptedContractDTO(UserContractAcceptance userContractAcceptance);
}
