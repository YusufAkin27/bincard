package akin.city_card.contract.service.abstacts;

import akin.city_card.contract.core.request.AcceptContractRequest;
import akin.city_card.contract.core.request.CreateContractRequest;
import akin.city_card.contract.core.request.RejectContractRequest;
import akin.city_card.contract.core.request.UpdateContractRequest;
import akin.city_card.contract.core.response.AcceptedContractDTO;
import akin.city_card.contract.core.response.ContractDTO;
import akin.city_card.contract.core.response.UserContractDTO;
import akin.city_card.contract.exceptions.ContractNotFoundException;
import akin.city_card.contract.model.Contract;
import akin.city_card.contract.model.ContractType;
import akin.city_card.response.ResponseMessage;
import akin.city_card.security.entity.SecurityUser;
import akin.city_card.security.exception.UserNotFoundException;

import java.util.List;

public interface ContractService {

    // Admin İşlemleri
    ResponseMessage createContract(CreateContractRequest request, String adminUsername);

    ResponseMessage updateContract(Long contractId, UpdateContractRequest request, String adminUsername);

    ResponseMessage deactivateContract(Long contractId, String adminUsername);

    ResponseMessage activateContract(Long contractId, String adminUsername);

    ContractDTO getContractById(Long contractId);

    List<ContractDTO> getAllContracts();

    List<ContractDTO> getActiveContracts();

    List<ContractDTO> getContractsByType(ContractType type);

    // Herkese Açık API'ler
    List<ContractDTO> getPublicActiveContracts();

    ContractDTO getLatestContractByType(ContractType type);

    ContractDTO getPublicContractById(Long contractId);

    // Kullanıcı İşlemleri
    List<UserContractDTO> getUserContracts(String username) throws UserNotFoundException;

    List<UserContractDTO> getMandatoryContractsForUser(String username) throws UserNotFoundException;

    List<UserContractDTO> getPendingContractsForUser(String username) throws UserNotFoundException;

    ResponseMessage acceptContract(String username, Long contractId, AcceptContractRequest request);

    ResponseMessage rejectContract(String username, Long contractId, RejectContractRequest request);

    List<AcceptedContractDTO> getAcceptedContracts(String username) throws UserNotFoundException;

    List<AcceptedContractDTO> getUserAcceptedContracts(String username) throws UserNotFoundException;

    // Otomatik Kabul İşlemleri
    void autoAcceptMandatoryContracts(SecurityUser user, String ipAddress, String userAgent);

    // Kontrol İşlemleri
    boolean hasUserAcceptedContract(String username, Long contractId) throws UserNotFoundException, ContractNotFoundException;

    boolean hasUserAcceptedAllMandatoryContracts(String username) throws UserNotFoundException;

    List<Contract> getUnacceptedMandatoryContracts(String username) throws UserNotFoundException;
}