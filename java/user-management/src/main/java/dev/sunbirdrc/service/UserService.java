package dev.sunbirdrc.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.sunbirdrc.config.KeycloakConfig;
import dev.sunbirdrc.config.PropertiesValueMapper;
import dev.sunbirdrc.dto.*;
import dev.sunbirdrc.entity.UserCredential;
import dev.sunbirdrc.entity.UserDetails;
import dev.sunbirdrc.exception.*;
import dev.sunbirdrc.repository.UserAttributeRepository;
import dev.sunbirdrc.repository.UserCredentialRepository;
import dev.sunbirdrc.repository.UserDetailsRepository;
import dev.sunbirdrc.utils.CipherEncoder;
import dev.sunbirdrc.utils.OtpUtil;
import dev.sunbirdrc.utils.RedisUtil;
import dev.sunbirdrc.utils.UserConstant;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.NonNull;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserService {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserService.class);
    public static final String HEADER_X_USER_TOKEN = "x-user-token";
    public static final String AUTH_KEY_BEARER = "Bearer";
    @Autowired
    private KeycloakConfig keycloakConfig;

    @Qualifier("systemKeycloak")
    @Autowired
    private Keycloak systemKeycloak;

    @Autowired
    private MailService mailService;

    @Autowired
    private OtpUtil otpUtil;

    @Autowired
    private PropertiesValueMapper valueMapper;

    @Autowired
    private UserDetailsRepository userDetailsRepository;

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CipherEncoder cipherEncoder;

    @Autowired
    private UserAttributeRepository userAttributeRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private RedisUtil redisUtil;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PropertiesValueMapper propMapping;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper mapper;


    @Value("${redis.token.expiry.in.minutes}")
    private long redisTokenExpiryInMinutes;
    public UsersResource getSystemUsersResource(){
        LOGGER.info("getting system keycloak resource");
        RealmResource realmResource = systemKeycloak.realm(valueMapper.getRealm());
        LOGGER.info("get realm details - {}", realmResource.toString());
        UsersResource users = realmResource.users();
        LOGGER.info("getting users - {}", users.list());
        return users;
    }

    public CredentialRepresentation createPasswordCredentials(String password) {
        CredentialRepresentation passwordCredentials = new CredentialRepresentation();
        passwordCredentials.setTemporary(false);
        passwordCredentials.setType(CredentialRepresentation.PASSWORD);
        passwordCredentials.setValue(password);
        return passwordCredentials;
    }

    public ClientsResource getSystemClientResource(){
        return systemKeycloak.realm(valueMapper.getRealm()).clients();
    }

    /**
     * It provides all details of user that exist in keycloak server.
     * @param userName
     * @return
     */
    public List<UserRepresentation> getUserDetails(String userName) {
        List<UserRepresentation> search = getSystemUsersResource().search(userName, true);
        LOGGER.info("get user details - {}", search);
        return search;
    }


    public boolean configureAdmin(UserDetailsDTO userDetailsDTO) {

        return false;
    }

    public UserTokenDetailsDTO loginAndGenerateKeycloakToken(UserLoginDTO userLoginDTO) {
        if (userLoginDTO != null && StringUtils.hasText(userLoginDTO.getUsername())
                && StringUtils.hasText(userLoginDTO.getPassword())) {

            String username = userLoginDTO.getUsername();
            LOGGER.info("username {}", username);
            List<UserRepresentation> userRepresentationList = getUserDetails(username);
            LOGGER.info("userRepresentationList {}", userRepresentationList);
            if (userRepresentationList != null && !userRepresentationList.isEmpty()) {

                Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                        .filter(userRepresentation -> username.equalsIgnoreCase(userRepresentation.getUsername()))
                        .findFirst();
            LOGGER.info("userRepresentationOptional {}", userRepresentationOptional);

                if (!userRepresentationOptional.isPresent()) {
                    throw new UserCredentialsException("Username missing.");
                }

                List<RoleRepresentation> roleRepresentationList = getSystemUsersResource()
                        .get(userRepresentationOptional.get().getId())
                        .roles().realmLevel().listEffective();

                LOGGER.info("roleRepresentationList {}", roleRepresentationList);

                try {
                    TokenManager tokenManager = keycloakConfig
                            .getUserKeycloak(userLoginDTO.getUsername(), userLoginDTO.getPassword()).tokenManager();

                    AccessTokenResponse accessTokenResponse = tokenManager.getAccessToken();

                    // save token in redis with key as username
                    redisUtil.putValueWithExpireTime(userLoginDTO.getUsername(), accessTokenResponse.getToken(), redisTokenExpiryInMinutes, TimeUnit.MINUTES);

                    return UserTokenDetailsDTO.builder()
                            .accessToken(accessTokenResponse.getToken())
                            .expiresIn(accessTokenResponse.getExpiresIn())
                            .refreshToken(accessTokenResponse.getRefreshToken())
                            .refreshExpiresIn(accessTokenResponse.getRefreshExpiresIn())
                            .tokenType(accessTokenResponse.getTokenType())
                            .scope(accessTokenResponse.getScope())
                            .userRepresentation(userRepresentationOptional.get())
                            .roleRepresentationList(roleRepresentationList)
                            .build();
                } catch (NotAuthorizedException e) {
                    LOGGER.error("Credentials have authorization issue",e);
                    throw new AuthorizationException("Invalid user credentials");
                } catch (Exception e) {
                    LOGGER.error("Unable to get user details",e);
                    throw new KeycloakUserException("Unable to get user details");
                }
            } else {
                LOGGER.info("User details not found");
                throw new UserCredentialsException("User details not found");
            }
        } else {
            LOGGER.info("User credentials are invalid");
            throw new UserCredentialsException("User credentials are invalid");
        }
    }

    public boolean registerUser(UserDetailsDTO userDTO){
        boolean status = false;

        if (userDTO != null && !StringUtils.isEmpty(userDTO.getUserName())) {

            UserRepresentation user = new UserRepresentation();
            user.setUsername(userDTO.getUserName());
            user.setFirstName(userDTO.getFirstName());
            user.setLastName(userDTO.getLastName());
            user.setEmail(userDTO.getEmail());
            user.setRequiredActions(Arrays.asList(UserConstant.VERIFY_MAIL_ACTION, UserConstant.UPDATE_PASSWORD_ACTION));
            user.setEnabled(false);

            Map<String, List<String>> customAttributes = new HashMap<>();
            customAttributes.put(UserConstant.ROLL_NO, Collections.singletonList(userDTO.getRollNo()));
            customAttributes.put(UserConstant.INSTITUTE_ID, Collections.singletonList(userDTO.getInstituteId()));
            customAttributes.put(UserConstant.INSTITUTE_NAME, Collections.singletonList(userDTO.getInstituteName()));
            customAttributes.put(UserConstant.PHONE_NUMBER, Collections.singletonList(userDTO.getPhoneNo()));

            user.setAttributes(customAttributes);

            try {
                Response response = getSystemUsersResource().create(user);

                if (response.getStatus() == HttpStatus.CREATED.value()) {
                    persistUserDetails(userDTO);
                    status = true;
                } else {
                    LOGGER.error("Unable to create user, systemKeycloak response - " + response.getStatusInfo());
                    throw new KeycloakUserException("Unable to create user in keycloak directory: " + response.getStatusInfo());
                }
            } catch (Exception e) {
                LOGGER.error("Unable to create user in systemKeycloak", e.getMessage());
                throw new KeycloakUserException("Unable to create user - error message: " + e.getMessage());
            }
        }
        return status;
    }

    public void persistUserDetails(UserDetailsDTO userDTO) throws Exception {
        if (userDTO != null && !StringUtils.isEmpty(userDTO.getUserName())) {
            List<UserRepresentation> userRepresentationList = getUserDetails(userDTO.getUserName());

            if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
                Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                        .filter(userRepresentation -> userDTO.getUserName().equalsIgnoreCase(userRepresentation.getUsername()))
                        .findFirst();

                if (userRepresentationOptional.isPresent()) {
                    UserRepresentation userRepresentation = userRepresentationOptional.get();

                    UserDetails claimUser = UserDetails.builder()
                            .userId(userRepresentation.getId())
                            .userName(userRepresentation.getUsername())
                            .firstName(userRepresentation.getFirstName())
                            .lastName(userRepresentation.getLastName())
                            .email(userRepresentation.getEmail())
                            .enabled(userRepresentation.isEnabled())
                            .rollNo(userDTO.getRollNo())
                            .instituteId(userDTO.getInstituteId())
                            .instituteName(userDTO.getInstituteName())
                            .phoneNo(userDTO.getPhoneNo())
                            .build();

                    userDetailsRepository.save(claimUser);
                    mailService.sendOtpMail(claimUser);
                }
            }
        } else {
            throw new UserNotFoundException("Invalid user details or username, while saving user in claim service");
        }
    }

    public boolean verifyMailOTP(UserOtpDTO userOtpDTO) throws Exception {
        if (userOtpDTO != null && !StringUtils.isEmpty(userOtpDTO.getUsername())) {

            List<UserRepresentation> userRepresentationList = getUserDetails(userOtpDTO.getUsername());

            if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
                Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                        .filter(userRepresentation ->
                                userOtpDTO.getUsername().equalsIgnoreCase(userRepresentation.getUsername()))
                        .findFirst();

                if (!userRepresentationOptional.isPresent()) {
                    throw new Exception("Username missing while verifying OTP");
                }


                boolean matched = otpUtil.verifyUserMailOtp(userRepresentationOptional.get().getId(), userOtpDTO.getOtp());

                if (matched) {
                    UserResource userResource = getSystemUsersResource().get(userRepresentationOptional.get().getId());

                    UserRepresentation existingUserRepresentation = userResource.toRepresentation();
                    List<String> requiredActions = existingUserRepresentation.getRequiredActions();

                    if (requiredActions != null && !requiredActions.isEmpty()) {
                        requiredActions = requiredActions.stream()
                                .filter(actionName -> !UserConstant.VERIFY_MAIL_ACTION.equals(actionName)
                                        && !UserConstant.UPDATE_PASSWORD_ACTION.equals(actionName))
                                .collect(Collectors.toList());
                    }

                    existingUserRepresentation.setRequiredActions(requiredActions);

                    CredentialRepresentation credential = createPasswordCredentials(userOtpDTO.getPassword());
                    existingUserRepresentation.setCredentials(Collections.singletonList(credential));
                    existingUserRepresentation.setEnabled(true);

                    userResource.update(existingUserRepresentation);

                    return true;
                }
            }
        }

        return false;
    }

    public void generateAdminOtp(AdminDTO adminDTO) throws Exception {
        if (adminDTO != null && !StringUtils.isEmpty(adminDTO.getUsername())) {
            String username = adminDTO.getUsername();

            List<UserRepresentation> userRepresentationList = getUserDetails(username);

            if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
                Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                        .filter(userRepresentation -> username.equalsIgnoreCase(userRepresentation.getUsername()))
                        .findFirst();

                if (userRepresentationOptional.isPresent()) {
                    UserRepresentation userRepresentation = userRepresentationOptional.get();

                    UsersResource usersResource = getSystemUsersResource();
                    List<RoleRepresentation> roleRepresentationList = usersResource.get(userRepresentation.getId()).roles().realmLevel().listEffective();

                    Optional<RoleRepresentation> roleRepresentationOptional = roleRepresentationList.stream()
                            .filter(roleRepresentation -> UserConstant.ADMIN_ROLE.equals(roleRepresentation.getName()))
                            .findFirst();

                    if (roleRepresentationOptional.isPresent()) {
                        UserDetails userDetails = UserDetails.builder()
                                .userId(userRepresentation.getId())
                                .userName(userRepresentation.getUsername())
                                .firstName(userRepresentation.getFirstName())
                                .lastName(userRepresentation.getLastName())
                                .email(userRepresentation.getEmail())
                                .enabled(userRepresentation.isEnabled())
                                .build();

                        mailService.sendOtpMail(userDetails);
                    } else {
                        throw new OtpException("User doesn't have role admin");
                    }
                }
            }
        }
    }

    public UserTokenDetailsDTO getAdminTokenByOtp(AdminLoginDTO adminLoginDTO) throws Exception {
        if (adminLoginDTO != null && !StringUtils.isEmpty(adminLoginDTO.getEmail())) {
            String username = adminLoginDTO.getEmail();

            List<UserRepresentation> userRepresentationList = getUserDetails(username);

            if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
                Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                        .filter(userRepresentation -> username.equalsIgnoreCase(userRepresentation.getUsername()))
                        .findFirst();

                if (!userRepresentationOptional.isPresent()) {
                    throw new OtpException("Username missing while verifying OTP");
                }
                ///////////////////////////////////////

//                UserRepresentation userRepresentation = userRepresentationOptional.get();
//                List<CredentialRepresentation> credentials = userRepresentation.getCredentials();
//                CredentialRepresentation credentialRepresentation = credentials.get(0);
//                credentialRepresentation.getSecretData();
//                credentialRepresentation.getValue();

                //////////////////////////////////

                if (otpUtil.verifyUserMailOtp(userRepresentationOptional.get().getId(), adminLoginDTO.getOtp())) {
                    TokenManager tokenManager = systemKeycloak.tokenManager();
                    AccessTokenResponse accessTokenResponse = tokenManager.getAccessToken();

                    return UserTokenDetailsDTO.builder()
                            .accessToken(accessTokenResponse.getToken())
                            .expiresIn(accessTokenResponse.getExpiresIn())
                            .tokenType(accessTokenResponse.getTokenType())
                            .scope(accessTokenResponse.getScope())
                            .build();
                } else {
                    throw new OtpException("OTP mismatch");
                }
            } else {
                throw new OtpException("Unable to get user details");
            }
        }else {
            throw new OtpException("OTP details missing");
        }
    }



    public BulkCustomUserResponseDTO addBulkUser(List<CustomUserDTO> bulkUserDTOList){

        if (bulkUserDTOList == null || bulkUserDTOList.isEmpty()) {
            throw new InvalidInputDataException("Invalid user data to process");
        } else if (bulkUserDTOList.size() > valueMapper.getBulkUserSizeLimit()) {
            throw new InvalidInputDataException("User size limit crossed - Bulk user allowed size: " + valueMapper.getBulkUserSizeLimit());
        } else {
            return processBulkUserData(bulkUserDTOList);
        }
    }

    public void pushBulkUserBG(BulkUserCreationDTO bulkUserCreationDTO){

//        if (bulkUserCreationDTO == null || bulkUserCreationDTO.getUserCreationList() == null
//                || bulkUserCreationDTO.getUserCreationList().isEmpty()) {
//            throw new InvalidInputDataException("Invalid user data to process");
//        } else if (bulkUserCreationDTO.getUserCreationList().size() > valueMapper.getBulkUserSizeLimit()) {
//            throw new InvalidInputDataException("User size limit crossed - Bulk user allowed size: " + valueMapper.getBulkUserSizeLimit());
//        } else if (!StringUtils.hasText(bulkUserCreationDTO.getEmail())){
//            throw new InvalidInputDataException("Invalid user data to process : master mail id is missing");
//        }else {

        if (validateHasuraUserDetails(bulkUserCreationDTO)) {
            BulkHasuraUsersDTO bulkHasuraUsersDTO = getHasuraUserToCreate(bulkUserCreationDTO.getUserCreationList());
            BulkCustomUserResponseDTO bulkCustomUserResponseDTO = processAffliationBulkUserData(bulkHasuraUsersDTO.getNewUsers());

            addHasuraStatusInBulkResponse(bulkCustomUserResponseDTO, bulkHasuraUsersDTO);
            mailService.sendBulkUserCreationNotification(bulkCustomUserResponseDTO, bulkUserCreationDTO.getEmail());

//            Redis cache for bulk user status
//            if (processHasuraUserCreation(bulkCustomUserResponseDTO)) {
//                try {
//                    TimeUnit timeUnit = otpUtil.getOtpTimeUnit();
//                    redisUtil.putValueWithExpireTime("bulk_user_status", toJson(bulkCustomUserResponseDTO), propMapping.getOtpTtlDuration(), timeUnit);
//                } catch (Exception e) {
//                    log.error("Error while saving bulk user creation details in redis cache", e);
//                }
//            }
        }
    }

    private boolean validateHasuraUserDetails(BulkUserCreationDTO bulkUserCreationDTO) {
        if (bulkUserCreationDTO == null || bulkUserCreationDTO.getUserCreationList() == null
                || bulkUserCreationDTO.getUserCreationList().isEmpty()) {
            throw new InvalidInputDataException("Invalid user data to process");
        } else if (bulkUserCreationDTO.getUserCreationList().size() > valueMapper.getBulkUserSizeLimit()) {
            throw new InvalidInputDataException("User size limit crossed - Bulk user allowed size: " + valueMapper.getBulkUserSizeLimit());
        } else if (!StringUtils.hasText(bulkUserCreationDTO.getEmail())){
            throw new InvalidInputDataException("Invalid user data to process : master mail id is missing");
        }

        String emailRegxPattern = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@"
                + "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";

        if (!Pattern.compile(emailRegxPattern).matcher(bulkUserCreationDTO.getEmail()).matches()) {
            throw new InvalidInputDataException("Invalid master mail id : " + bulkUserCreationDTO.getEmail());
        }

        for (CustomUserDTO customUserDTO : bulkUserCreationDTO.getUserCreationList()) {
            if (!StringUtils.hasText(customUserDTO.getEmail()) || !StringUtils.hasText(customUserDTO.getUsername())) {
                throw new InvalidInputDataException("User email/username is missing");
            }

            boolean isValidMail = Pattern.compile(emailRegxPattern).matcher(customUserDTO.getEmail()).matches();
            boolean isValidUsername = Pattern.compile(emailRegxPattern).matcher(customUserDTO.getUsername()).matches();

            if (!isValidMail) {
                throw new InvalidInputDataException("Invalid user mail id: " + customUserDTO.getEmail());
            }
            if (!isValidUsername) {
                throw new InvalidInputDataException("Invalid username: " + customUserDTO.getUsername());
            }

            if (!StringUtils.hasText(customUserDTO.getPassword())) {
                throw new InvalidInputDataException("Password is missing for " + customUserDTO.getEmail());
            }

            if (!StringUtils.hasText(customUserDTO.getRoleName())) {
                throw new InvalidInputDataException("Role is missing for " + customUserDTO.getEmail());
            }

            if (UserConstant.ASSESSOR_ROLE.equalsIgnoreCase(customUserDTO.getRoleName())
                    && !StringUtils.hasText(customUserDTO.getCode())) {
                throw new InvalidInputDataException("Code is missing for assessor " + customUserDTO.getEmail());
            }
        }

        return true;
    }

    private void addHasuraStatusInBulkResponse(BulkCustomUserResponseDTO bulkCustomUserResponseDTO,
                                               BulkHasuraUsersDTO bulkHasuraUsersDTO) {

        if (bulkCustomUserResponseDTO != null && bulkCustomUserResponseDTO.getFailedUser() != null) {
            List<CustomUserResponseDTO> failedUser = bulkCustomUserResponseDTO.getFailedUser();

            failedUser.addAll(getHasuraExistedUserList(bulkHasuraUsersDTO));
        }
    }

    /**
     * @param bulkHasuraUsersDTO
     * @return
     */
    private List<CustomUserResponseDTO> getHasuraExistedUserList(BulkHasuraUsersDTO bulkHasuraUsersDTO) {
        List<CustomUserResponseDTO> customUserResponseDTOList = new ArrayList<>();

        if (bulkHasuraUsersDTO != null && bulkHasuraUsersDTO.getExitedUsers() != null
                && !bulkHasuraUsersDTO.getExitedUsers().isEmpty()) {

            customUserResponseDTOList = bulkHasuraUsersDTO.getExitedUsers().stream()
                    .map(customUserDTO -> CustomUserResponseDTO.builder()
                            .email(customUserDTO.getEmail())
                            .firstName(customUserDTO.getFirstName())
                            .lastName(customUserDTO.getLastName())
                            .roleName(customUserDTO.getRoleName())
                            .code(customUserDTO.getCode())
                            .phoneNumber(customUserDTO.getPhoneNumber())
                            .status("User already exists in DB (Hasura)")
                            .build())
                    .collect(Collectors.toList());
        }

        return customUserResponseDTOList;
    }


    private boolean generateHasuraUser(HasuraUserRequestDTO hasuraUserRequestDTO) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + propMapping.getHasuraAccessToken());
            headers.setContentType(MediaType.APPLICATION_JSON);
            JsonNode jsonNodeObject = mapper.convertValue(hasuraUserRequestDTO, JsonNode.class);

            ResponseEntity response = restTemplate.exchange(propMapping.getHasuraBulkUserCreateAPI(), HttpMethod.POST,
                    new HttpEntity<>(jsonNodeObject, headers), String.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                return true;
            }
        } catch (Exception e) {
            log.error(">>>>>>>>>>>> Error while generating user in hasura ", e);
        }

        return false;
    }


    /**
     * @param bulkUserDTOList
     * @return
     */
    private BulkHasuraUsersDTO getHasuraUserToCreate(List<CustomUserDTO> bulkUserDTOList) {
        BulkHasuraUsersDTO bulkHasuraUsersDTO = new BulkHasuraUsersDTO();
        List<CustomUserDTO> exitedUsers = new ArrayList<>();
        List<CustomUserDTO> newUsers = new ArrayList<>();

        for (CustomUserDTO customUserDTO : bulkUserDTOList) {
            HasuraUseCheckRequestDTO hasuraUseCheckRequestDTO = HasuraUseCheckRequestDTO.builder()
                    .email(customUserDTO.getEmail())
                    .build();

            if (isNewHasuraUser(hasuraUseCheckRequestDTO)) {
                newUsers.add(customUserDTO);
            } else {
                exitedUsers.add(customUserDTO);
            }
        }
        bulkHasuraUsersDTO.setNewUsers(newUsers);
        bulkHasuraUsersDTO.setExitedUsers(exitedUsers);

        return bulkHasuraUsersDTO;
    }

    private boolean isNewHasuraUser(HasuraUseCheckRequestDTO hasuraUseCheckRequestDTO) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + propMapping.getHasuraAccessToken());
            headers.setContentType(MediaType.APPLICATION_JSON);
            JsonNode jsonNodeObject = mapper.convertValue(hasuraUseCheckRequestDTO, JsonNode.class);

            ResponseEntity<HasuraUserCheckResponseDTO> response = restTemplate
                    .exchange(propMapping.getHasuraUserCheckAPI(), HttpMethod.POST,
                            new HttpEntity<>(jsonNodeObject, headers), HasuraUserCheckResponseDTO.class);

            HasuraUserCheckResponseDTO userCheckResponseDTO = response.getBody();

            if (response.getStatusCode() == HttpStatus.OK) {
                if (userCheckResponseDTO != null ) {
                    if ((userCheckResponseDTO.getAssessors() != null && userCheckResponseDTO.getAssessors().isEmpty())
                            && (userCheckResponseDTO.getRegulator() != null && userCheckResponseDTO.getRegulator().isEmpty())
                            && (userCheckResponseDTO.getInstitutes() != null && userCheckResponseDTO.getInstitutes().isEmpty())
                    ) {
                        return true;
                    } else {
                        return false;
                    }
                }
            }
        } catch (Exception e) {
            log.error(">>>>>>>>>>>> Error while generating user in hasura ", e);
            throw new CustomException("Unable to check user in Hasura system: " + e.getMessage());
        }
        return false;
    }



    private String toJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            // Handle the exception
            return null;
        }
    }

    public BulkCustomUserResponseDTO getBulkUserStatus(){

        try {
            String bulkUserStatus = redisUtil.getValue("bulk_user_status");

            BulkCustomUserResponseDTO bulkCustomUserResponseDTO = fromJson(bulkUserStatus, BulkCustomUserResponseDTO.class);

            return bulkCustomUserResponseDTO;
        } catch (Exception e) {
            log.error("Error while getting bulk user data from redis cache", e);
            throw new CustomException("Unable to fetch bulk user creation data");
        }
    }

    private <T> T fromJson(String json, Class<T> valueType) {
        try {
            return objectMapper.readValue(json, valueType);
        } catch (JsonProcessingException e) {
            // Handle the exception
            return null;
        }
    }

    /**
     * TODO: Refactor method for simplicity
     *
     * @param bulkUserDTOList
     * @return
     */
    public BulkCustomUserResponseDTO processAffliationBulkUserData(List<CustomUserDTO> bulkUserDTOList) {
        BulkCustomUserResponseDTO bulkCustomUserResponseDTO = new BulkCustomUserResponseDTO();
        List<CustomUserResponseDTO> succeedUserList = new ArrayList<>();
        List<CustomUserResponseDTO> failedUserList = new ArrayList<>();

        for (CustomUserDTO customUserDTO : bulkUserDTOList) {
            CustomUserResponseDTO customUserResponseDTO = CustomUserResponseDTO.builder()
                    .email(customUserDTO.getEmail())
                    .firstName(customUserDTO.getFirstName())
                    .lastName(customUserDTO.getLastName())
                    .roleName(customUserDTO.getRoleName())
                    .code(customUserDTO.getCode())
                    .phoneNumber(customUserDTO.getPhoneNumber())
                    .build();

            if (isUserExist(customUserDTO.getUsername())) {
                LOGGER.error(">>> User is already exist in user management");
                customUserResponseDTO.setStatus("User already exists in DB (UM)");
                failedUserList.add(customUserResponseDTO);
            } else {
                UserRepresentation userRepresentation = new UserRepresentation();
                userRepresentation.setUsername(customUserDTO.getUsername());
                userRepresentation.setFirstName(customUserDTO.getFirstName());
                userRepresentation.setLastName(customUserDTO.getLastName());
                userRepresentation.setEmail(customUserDTO.getEmail());
                userRepresentation.setCredentials(Collections.singletonList(createPasswordCredentials(customUserDTO.getPassword())));
                userRepresentation.setEnabled(true);

                Map<String, List<String>> customAttributes = new HashMap<>();
                customAttributes.put(UserConstant.ROLE_NAME, Collections.singletonList(customUserDTO.getRoleName()));
                customAttributes.put(UserConstant.PHONE_NUMBER, Collections.singletonList(customUserDTO.getPhoneNumber()));
                customAttributes.put(UserConstant.MODULE, Collections.singletonList("AFFILIATION"));

                userRepresentation.setAttributes(customAttributes);

                try {
                    Response response = getSystemUsersResource().create(userRepresentation);

                    if (response.getStatus() == HttpStatus.CREATED.value()) {
                        persistUserDetailsWithCredentials(customUserDTO);

                        customUserResponseDTO.setUserId(getKeycloakUserId(customUserDTO.getUsername()));

                        boolean isHasuraUserCreated = createHasuraUser(customUserResponseDTO);

                        if (isHasuraUserCreated) {
                            customUserResponseDTO.setStatus("User has been created successfully");
                            succeedUserList.add(customUserResponseDTO);
                        } else {
                            LOGGER.error("Unable to create user in hasura - " + response.getStatusInfo());

                            customUserResponseDTO.setStatus("Faild to create user - something went wrong in Hasura");
                            failedUserList.add(customUserResponseDTO);
                        }
                    } else {
                        LOGGER.error("Unable to create custom user, systemKeycloak response - " + response.getStatusInfo());

                        customUserResponseDTO.setStatus("Faild to create user - Unable to create user in keycloak: " + response.getStatus());
                        failedUserList.add(customUserResponseDTO);
                    }
                } catch (Exception e) {
                    LOGGER.error("Unable to create custom user in systemKeycloak", e.getMessage());
                    customUserResponseDTO.setStatus("Faild to create user");
                    failedUserList.add(customUserResponseDTO);
                }
            }
        }

        bulkCustomUserResponseDTO.setSucceedUser(succeedUserList);
        bulkCustomUserResponseDTO.setFailedUser(failedUserList);

        return bulkCustomUserResponseDTO;
    }


    private boolean createHasuraUser(CustomUserResponseDTO customUserResponseDTO) {
        if (customUserResponseDTO != null) {

            List<RegulatorDTO> regulators = new ArrayList<>();
            List<AssessorDTO> assessors = new ArrayList<>();
            HasuraUserRequestDTO hasuraUserRequestDTO = HasuraUserRequestDTO.builder()
                    .regulators(regulators)
                    .assessors(assessors)
                    .build();

            if (UserConstant.ASSESSOR_ROLE.equalsIgnoreCase(customUserResponseDTO.getRoleName())) {
                AssessorDTO assessorDTO = AssessorDTO.builder()
                        .user_id(customUserResponseDTO.getUserId())
                        .phonenumber(customUserResponseDTO.getPhoneNumber())
                        .email(customUserResponseDTO.getEmail())
                        .name(customUserResponseDTO.getFirstName() + " " + customUserResponseDTO.getLastName())
                        .lname(customUserResponseDTO.getLastName())
                        .fname(customUserResponseDTO.getFirstName())
                        .role(customUserResponseDTO.getRoleName())
                        .code(customUserResponseDTO.getCode())
                        .build();

                assessors.add(assessorDTO);
            } else {
                RegulatorDTO regulatorDTO = RegulatorDTO.builder()
                        .user_id(customUserResponseDTO.getUserId())
                        .phonenumber(customUserResponseDTO.getPhoneNumber())
                        .email(customUserResponseDTO.getEmail())
                        .full_name(customUserResponseDTO.getFirstName() + " " + customUserResponseDTO.getLastName())
                        .lname(customUserResponseDTO.getLastName())
                        .fname(customUserResponseDTO.getFirstName())
                        .role(customUserResponseDTO.getRoleName())
                        .workingstatus("valid")
                        .build();

                regulators.add(regulatorDTO);
            }


            return generateHasuraUser(hasuraUserRequestDTO);
        }

        return false;
    }

    private String getKeycloakUserId(String username) {
        List<UserRepresentation> userRepresentationList = getUserDetails(username);

        if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
            Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream().findFirst();

            if (userRepresentationOptional.isPresent()) {
                return userRepresentationOptional.get().getId();
            } else {
                throw new UserNotFoundException("Unable to find user id for : " + username);
            }
        } else {
            throw new UserNotFoundException("Unable to find user for : " + username);
        }
    }

    public BulkCustomUserResponseDTO processBulkUserData(List<CustomUserDTO> bulkUserDTOList) {
        BulkCustomUserResponseDTO bulkCustomUserResponseDTO = new BulkCustomUserResponseDTO();
        List<CustomUserResponseDTO> succeedUserList = new ArrayList<>();
        List<CustomUserResponseDTO> failedUserList = new ArrayList<>();

        for (CustomUserDTO customUserDTO : bulkUserDTOList) {
            CustomUserResponseDTO customUserResponseDTO = CustomUserResponseDTO.builder()
                    .email(customUserDTO.getEmail())
                    .firstName(customUserDTO.getFirstName())
                    .lastName(customUserDTO.getLastName())
                    .roleName(customUserDTO.getRoleName())
                    .build();

            if (isUserExist(customUserDTO.getUsername())) {
                LOGGER.error(">>> User is already exist in user management");
                customUserResponseDTO.setStatus("Faild to create user - User is already exist in user management DB");
                failedUserList.add(customUserResponseDTO);
            } else {
                UserRepresentation userRepresentation = new UserRepresentation();
                userRepresentation.setUsername(customUserDTO.getUsername());
                userRepresentation.setFirstName(customUserDTO.getFirstName());
                userRepresentation.setLastName(customUserDTO.getLastName());
                userRepresentation.setEmail(customUserDTO.getEmail());
                userRepresentation.setCredentials(Collections.singletonList(createPasswordCredentials(customUserDTO.getPassword())));
                userRepresentation.setEnabled(true);

                try {
                    Response response = getSystemUsersResource().create(userRepresentation);

                    if (response.getStatus() == HttpStatus.CREATED.value()) {
                        String userId = assignCustomUserRole(customUserDTO);
                        persistUserDetailsWithCredentials(customUserDTO);

                        customUserResponseDTO.setUserId(userId);
                        customUserResponseDTO.setStatus("User has been created successfully - mail in progress");
                        succeedUserList.add(customUserResponseDTO);
                    } else {
                        LOGGER.error("Unable to create custom user, systemKeycloak response - " + response.getStatusInfo());

                        customUserResponseDTO.setStatus("Faild to create user - Unable to create user in keycloak: " + response.getStatus());
                        failedUserList.add(customUserResponseDTO);
//                    throw new KeycloakUserException("Unable to create custom user in keycloak directory: " + response.getStatusInfo());
                    }
                } catch (Exception e) {
                    LOGGER.error("Unable to create custom user in systemKeycloak", e.getMessage());
                    customUserResponseDTO.setStatus("Faild to create user");
                    failedUserList.add(customUserResponseDTO);
//                throw new KeycloakUserException("Unable to create custom user - error message: " + e.getMessage());
                }
            }
        }

        bulkCustomUserResponseDTO.setSucceedUser(succeedUserList);
        bulkCustomUserResponseDTO.setFailedUser(failedUserList);

        processUserCreationMailNotification(bulkCustomUserResponseDTO);

        return bulkCustomUserResponseDTO;
    }

    @Async
    private void processUserCreationMailNotification(@NonNull BulkCustomUserResponseDTO bulkCustomUserResponseDTO) {
        if (bulkCustomUserResponseDTO.getSucceedUser() != null && !bulkCustomUserResponseDTO.getSucceedUser().isEmpty()) {
            for (CustomUserResponseDTO customUserResponseDTO : bulkCustomUserResponseDTO.getSucceedUser()) {

                CustomUserDTO customUserDTO = CustomUserDTO.builder()
                        .email(customUserResponseDTO.getEmail())
                        .firstName(customUserResponseDTO.getFirstName())
                        .lastName(customUserResponseDTO.getLastName())
                        .roleName(customUserResponseDTO.getRoleName())
                        .build();


                mailService.sendUserCreationNotification(customUserDTO);
            }
        }
    }

    /**
     * @param customUserDTO
     */
    private String assignCustomUserRole(CustomUserDTO customUserDTO) {
        List<UserRepresentation> userRepresentationList = getUserDetails(customUserDTO.getUsername());

        if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
            Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream().findFirst();

            if (userRepresentationOptional.isPresent()) {
                List<RoleRepresentation> roleToAdd = new LinkedList<>();

                UserResource user = systemKeycloak
                        .realm(valueMapper.getRealm())
                        .users()
                        .get(userRepresentationOptional.get().getId());

                roleToAdd.add(systemKeycloak
                        .realm(valueMapper.getRealm())
                        .roles()
                        .get(customUserDTO.getRoleName())
                        .toRepresentation()
                );
                user.roles().realmLevel().add(roleToAdd);

                return userRepresentationOptional.get().getId();
            } else {
                throw new RoleNotFoundException("Unable to find role");
            }
        } else {
            throw new RoleNotFoundException("Unable to find role");
        }
    }


    /**
     * Password is being saved as plain text - need to refactor.
     *
     * @param customUserDTO
     * @throws Exception
     */
    public void persistUserDetailsWithCredentials(@NonNull CustomUserDTO customUserDTO) throws Exception {
        Optional<UserCredential> byUserName = userCredentialRepository.findByUserName(customUserDTO.getUsername());
        UserCredential userCredential = null;
        if(byUserName.isPresent()){
            userCredential = byUserName.get();
            userCredential.setPassword(cipherEncoder.encodeText(customUserDTO.getPassword()));
        } else {
            userCredential = UserCredential.builder()
                    .userName(customUserDTO.getUsername())
                    .password(cipherEncoder.encodeText(customUserDTO.getPassword()))
                    .build();
        }
        userCredentialRepository.save(userCredential);
    }

    /**
     * @param customUsernameDTO
     * @throws Exception
     */
    public void generateCustomUserOtp(CustomUsernameDTO customUsernameDTO) {
        if (customUsernameDTO != null && !StringUtils.isEmpty(customUsernameDTO.getUsername())) {
            String username = customUsernameDTO.getUsername();

            if (!isUserExist(username)) {
                throw new UserNotFoundException("User is not available in our system");
            }

            List<UserRepresentation> userRepresentationList = getUserDetails(username);

            if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
                Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                        .filter(userRepresentation -> username.equalsIgnoreCase(userRepresentation.getUsername()))
                        .findFirst();

                if (userRepresentationOptional.isPresent()) {
                    UserRepresentation userRepresentation = userRepresentationOptional.get();

                    UserDetails userDetails = UserDetails.builder()
                            .userId(userRepresentation.getId())
                            .userName(userRepresentation.getUsername())
                            .firstName(userRepresentation.getFirstName())
                            .lastName(userRepresentation.getLastName())
                            .email(userRepresentation.getEmail())
                            .enabled(userRepresentation.isEnabled())
                            .build();

                    mailService.sendOtpMail(userDetails);
                }
            } else {
                throw new UserNotFoundException("User is not available in Keycloak System");
            }
        } else {
            throw new InvalidInputDataException("Invalid input data");
        }
    }

    /**
     * @param customUserLoginDTO
     * @return
     * @throws Exception
     */
    public UserTokenDetailsDTO getCustomUserTokenByOtp(CustomUserLoginDTO customUserLoginDTO) throws Exception {
        if (customUserLoginDTO != null && !StringUtils.isEmpty(customUserLoginDTO.getEmail())) {
            LOGGER.info("CustomUserLoginDTO : {}", customUserLoginDTO);
            String username = customUserLoginDTO.getEmail();
            List<UserRepresentation> userRepresentationList = getUserDetails(username);
            LOGGER.info("userRepresentationList {}", userRepresentationList);
            if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
                Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                        .filter(userRepresentation -> username.equalsIgnoreCase(userRepresentation.getUsername()))
                        .findFirst();
                LOGGER.info("userRepresentationOptional {}", userRepresentationOptional);
                if (!userRepresentationOptional.isPresent()) {
                    throw new OtpException("Username missing while verifying OTP");
                }

                if (otpUtil.verifyUserMailOtp(userRepresentationOptional.get().getId(), customUserLoginDTO.getOtp())) {
                    try {
                        List<RoleRepresentation> roleRepresentationList = getSystemUsersResource()
                                .get(userRepresentationOptional.get().getId())
                                .roles().realmLevel().listEffective();

                        TokenManager tokenManager = keycloakConfig
                                .getUserKeycloak(customUserLoginDTO.getEmail(),
                                        getCustomUserCredentail(customUserLoginDTO.getEmail()))
                                .tokenManager();

                        AccessTokenResponse accessTokenResponse = tokenManager.getAccessToken();

                        return UserTokenDetailsDTO.builder()
                                .accessToken(accessTokenResponse.getToken())
                                .expiresIn(accessTokenResponse.getExpiresIn())
                                .refreshToken(accessTokenResponse.getRefreshToken())
                                .refreshExpiresIn(accessTokenResponse.getRefreshExpiresIn())
                                .tokenType(accessTokenResponse.getTokenType())
                                .scope(accessTokenResponse.getScope())
                                .userRepresentation(userRepresentationOptional.get())
                                .roleRepresentationList(roleRepresentationList)
                                .build();
                    } catch (NotAuthorizedException e) {
                        e.printStackTrace();
                        throw new AuthorizationException("Credentials have authorization issue");
                    } catch (Exception e) {
                        e.printStackTrace();
                        throw new KeycloakUserException("Unable to get user details - Update user");
                    }
                } else {
                    throw new OtpException("OTP mismatch");
                }
            } else {
                throw new OtpException("Unable to get user details");
            }
        }else {
            throw new OtpException("OTP details missing");
        }
    }


    /**
     * Password is being saved as plain text - Need to refactor in future
     * @param username
     * @return
     */
    private @NonNull String getCustomUserCredentail(@NonNull String username) {
        Optional<UserCredential> userCredentialOptional = userCredentialRepository.findByUserName(username);
        LOGGER.info("userRepresentationOptional1 {}", userCredentialOptional);
        if (userCredentialOptional.isPresent()) {
            LOGGER.info("Credentials {} and {}",username, cipherEncoder.decodeText(userCredentialOptional.get().getPassword()));
            return cipherEncoder.decodeText(userCredentialOptional.get().getPassword());
        } else {
            throw new UserNotFoundException("User is not configured properly in User management system");
        }
    }

    public void deleteBulkUSer(List<CustomUserDeleteDTO> customUserDeleteDTOList) {
        if (customUserDeleteDTOList != null && !customUserDeleteDTOList.isEmpty()) {
            for (CustomUserDeleteDTO customUserDeleteDTO : customUserDeleteDTOList) {
                deleteUser(customUserDeleteDTO.getEmail());
            }
        }
    }

    public void deleteUser(String username){
        List<UserRepresentation> userRepresentationList = getUserDetails(username);

        if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
            Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                    .filter(userRepresentation -> username.equalsIgnoreCase(userRepresentation.getUsername()))
                    .findFirst();

            if (!userRepresentationOptional.isPresent()) {
                throw new UserNotFoundException("Unable to find user in keycloak " + username);
            }

            settleUserDeletionInDB(username);

            UsersResource usersResource = getSystemUsersResource();
            usersResource.get(userRepresentationOptional.get().getId()).remove();
        }


    }

    private void settleUserDeletionInDB(@NonNull String username) {
        Optional<UserCredential> userCredentialOptional = userCredentialRepository.findByUserName(username);

        if (!userCredentialOptional.isPresent()) {
            throw new UserNotFoundException("Unable to fine user in User Management service " );
        } else {
            userCredentialRepository.delete(userCredentialOptional.get());
        }
    }

    /**
     * @param customUserUpdateDTO
     */
    public void updateUser(CustomUserUpdateDTO customUserUpdateDTO){
        List<UserRepresentation> userRepresentationList = getUserDetails(customUserUpdateDTO.getUsername());

        if (userRepresentationList != null && !userRepresentationList.isEmpty()) {
            Optional<UserRepresentation> userRepresentationOptional = userRepresentationList.stream()
                    .filter(userRepresentation -> customUserUpdateDTO.getUsername().equalsIgnoreCase(userRepresentation.getUsername()))
                    .findFirst();

            if (!userRepresentationOptional.isPresent()) {
                throw new UserNotFoundException("Unable to find user in keycloak " + customUserUpdateDTO.getUsername());
            }

            UserRepresentation user = new UserRepresentation();
            user.setFirstName(customUserUpdateDTO.getFirstName());
            user.setLastName(customUserUpdateDTO.getLastName());

            UserResource userResource = getSystemUsersResource().get(userRepresentationOptional.get().getId());
            userResource.update(user);

            assignRole(customUserUpdateDTO.getRoleNames(), userRepresentationOptional.get().getId());
        }
    }

    private void assignRole(List<String> roleNames, String userId) {
        if (roleNames != null && !roleNames.isEmpty()) {
            List<RoleRepresentation> roleToAdd = new LinkedList<>();

            for (String roleName : roleNames) {
                try {

                    RoleRepresentation roleRepresentation = systemKeycloak.realm(valueMapper.getRealm())
                            .roles()
                            .get(roleName)
                            .toRepresentation();

                    roleToAdd.add(roleRepresentation);
                } catch (NotFoundException exception) {
                    throw new RoleNotFoundException("Role name list is not valid");
                }
            }

            UserResource user = getSystemUsersResource().get(userId);

            List<RoleRepresentation> roleRepresentationList = user.roles().realmLevel().listEffective();
            user.roles().realmLevel().remove(roleRepresentationList);
            user.roles().realmLevel().add(roleToAdd);
        }
    }

    public CustomUserResponseDTO createCustomUser(CustomUserDTO customUserDTO) {
        if (customUserDTO != null && !StringUtils.isEmpty(customUserDTO.getUsername())) {
            if (isUserExist(customUserDTO.getUsername())) {
                throw new UserConflictException("User is already exist in user management in DB");
            }

            CustomUserResponseDTO customUserResponseDTO = CustomUserResponseDTO.builder()
                    .email(customUserDTO.getEmail())
                    .firstName(customUserDTO.getFirstName())
                    .lastName(customUserDTO.getLastName())
                    .roleName(customUserDTO.getRoleName())
                    .build();

            UserRepresentation userRepresentation = new UserRepresentation();
            userRepresentation.setUsername(customUserDTO.getUsername());
            userRepresentation.setFirstName(customUserDTO.getFirstName());
            userRepresentation.setLastName(customUserDTO.getLastName());
            userRepresentation.setEmail(customUserDTO.getEmail());
            userRepresentation.setCredentials(Collections.singletonList(createPasswordCredentials(customUserDTO.getPassword())));
            userRepresentation.setEnabled(true);

            try {
                Response response = getSystemUsersResource().create(userRepresentation);

                if (response.getStatus() == HttpStatus.CREATED.value()) {
                    String userId = assignCustomUserRole(customUserDTO);
                    persistUserDetailsWithCredentials(customUserDTO);

                    customUserResponseDTO.setUserId(userId);
                    customUserResponseDTO.setStatus("User has been created successfully - mail in progress");
                    mailService.sendUserCreationNotification(customUserDTO);

                    return customUserResponseDTO;
                } else {
                    LOGGER.error("Unable to create user, systemKeycloak response - " + response.getStatusInfo());
                    throw new KeycloakUserException("Unable to create user in keycloak directory: " + response.getStatusInfo());
                }
            } catch (Exception e) {
                LOGGER.error("Unable to create user in systemKeycloak", e.getMessage());
                throw new KeycloakUserException("Unable to create user - error message: " + e.getMessage());
            }
        } else {
            throw new InvalidInputDataException("Invalid input for user creation");
        }
    }

    public boolean isUserExist(@NonNull String username) {
        LOGGER.info("Check user exists payload ||| ------ {}", username);
        Optional<UserCredential> userCredentialOptional = userCredentialRepository.findByUserName(username);
        LOGGER.info("Check user exists ||| response ------ {}", userCredentialOptional);
        if(userCredentialOptional.isEmpty()) {
            return false;
        }
        if (userCredentialOptional.isPresent()) {
            return true;
        } else {
            return false;
        }
    }

    public List getUserByAttribute(final JsonNode body) throws SQLException {
        String fieldName = body.get("fieldName").asText();
        String fieldValue = body.get("fieldValue").asText();
        int offset = body.get("offset").asInt();
        int limit = body.get("limit").asInt();
        LOGGER.info("Fetching user info by field {} and value {} with offset {} and limit {}",fieldName, fieldValue, offset, limit);
        return getUserListByAttribute(fieldName,fieldValue, offset, limit);
    }

    public List getUserListByAttribute(final String fieldName, final String fieldValue, int offset, int limit) throws SQLException {

        List<UserAttributeModel> userByAttribute = getUserAttribute(fieldName, fieldValue,offset,limit);
        if(userByAttribute == null || userByAttribute.isEmpty()){
            LOGGER.info("No records found.");
            return Collections.EMPTY_LIST;
        }
        LOGGER.info("Records found {}",userByAttribute);
        List<String> collect = userByAttribute.stream().map(UserAttributeModel::getUserId).collect(Collectors.toList());

        Map<String, UserRepresentation> userRepresentationMap = getStringUserRepresentationMap(collect);
        if(userRepresentationMap.isEmpty()){
            LOGGER.info("No UserRepresentation records found for {}",collect);
            return Collections.EMPTY_LIST;
        }
        return new ArrayList<>(userRepresentationMap.values());
    }

    public List<UserAttributeModel> getUserAttribute(String fieldName, String fieldValue, int offset, int limit) {
        return userAttributeRepository.findUserByAttribute(fieldName, fieldValue,offset,limit);
    }

    private Map<String, UserRepresentation> getStringUserRepresentationMap(List<String> collect) throws SQLException {
        Connection connection = Objects.requireNonNull(jdbcTemplate.getDataSource()).getConnection();
        String formattedString = getFormattedStringFromCollection(collect);
        Map<String, UserRepresentation> userRepresentationMap = new HashMap<>();
        ResultSet resultSet = null;
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = connection.prepareStatement(formattedString);
            resultSet = preparedStatement.executeQuery();
            if (resultSet != null) {
                while (resultSet.next()) {
                    String id = resultSet.getString("id");
                    UserRepresentation userRepresentation = null;
                    if (userRepresentationMap.containsKey(id)) {
                        userRepresentation = userRepresentationMap.get(id);
                        userRepresentation.singleAttribute(resultSet.getString("name"), resultSet.getString("value"));
                    } else {
                        userRepresentation = new UserRepresentation();
                        userRepresentation.setId(id);
                        userRepresentation.setUsername(resultSet.getString("username"));
                        userRepresentation.setEnabled(resultSet.getBoolean("enabled"));
                        userRepresentation.setEmail(resultSet.getString("email"));
                        userRepresentation.setFirstName(resultSet.getString("first_name"));
                        userRepresentation.setLastName(resultSet.getString("last_name"));
                        userRepresentation.singleAttribute(resultSet.getString("name"), resultSet.getString("value"));
                        userRepresentationMap.put(id, userRepresentation);
                    }
                }
            }
        } catch (Exception exception){
            LOGGER.error("Exception while processing data from DB.",exception);
        } finally {
            if(resultSet != null){
                resultSet.close();
            }
            if(preparedStatement != null){
                preparedStatement.close();
            }
            if(connection != null){
                connection.close();
            }
        }
        LOGGER.info("userRepresentationMap {}",userRepresentationMap);
        return userRepresentationMap;
    }

    private String getFormattedStringFromCollection(List<String> collect) {
        StringBuffer sbf = new StringBuffer();
        sbf.append("select ue.*,ua.name,ua.value  from user_entity ue join user_attribute ua on ua.user_id = ue.id WHERE ue.id IN (");
        collect.stream().forEach(item -> {
            sbf.append("'" + item + "'");
            sbf.append(",");
        });
        String substring = sbf.substring(0, sbf.lastIndexOf(","));
        substring = substring + (" )");
        LOGGER.info("Query to be Executed {}",substring);
        return substring;
    }

    /**
     * get user by keycloak ID
     * @param userId
     * @return
     */
    public UserResource getUserDetailsById(String userId) {
        UserResource search = getSystemUsersResource().get(userId);
        LOGGER.info("get user details - {}", search);
        return search;
    }

    /**
     * log out user
     * @param userId
     */
    public void logout(String userId, Map<String, String> headers) {
        UserResource userDetailsById = getUserDetailsById(userId);
        userDetailsById.logout();
        // invalidate user token
        invalidateUserToken(headers);
    }

    private void invalidateUserToken(Map<String, String> headers) {
        LOGGER.info("LOG OUT METHOD - Header Map - {}", headers);
        if(headers!= null && !headers.isEmpty()) {
            String authorization = headers.get(HEADER_X_USER_TOKEN);
            LOGGER.info("LOG OUT METHOD - Header Map - auth key {}", authorization);
            if(authorization != null && !authorization.isBlank()) {
                if(authorization.trim().startsWith(AUTH_KEY_BEARER)){
                    LOGGER.info("LOG OUT METHOD - auth key start with Bearer - {}", authorization);
                    int separatorIndex = authorization.trim().indexOf(" ");
                    LOGGER.info("LOG OUT METHOD - auth key start with Bearer - trim bearer | space index - {}", separatorIndex);
                    if(separatorIndex > 0 && separatorIndex < authorization.trim().length()) {
                        authorization = authorization.trim().substring(separatorIndex+1);
                        LOGGER.info("LOG OUT METHOD - auth key start without Bearer - {}", authorization);
                    }
                }
                LOGGER.info("LOG OUT METHOD - auth key final - {}", authorization);
                LOGGER.info("LOG OUT METHOD - revoking token ");
                // revoke token
                keycloakConfig.systemKeycloak().tokenManager().invalidate(authorization);
                LOGGER.info("LOG OUT METHOD - token revoked");
            }
        }
    }
}
