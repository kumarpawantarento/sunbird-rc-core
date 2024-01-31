package dev.sunbirdrc.controller;


import com.fasterxml.jackson.databind.JsonNode;
import dev.sunbirdrc.dto.*;
import dev.sunbirdrc.entity.UserDetails;
import dev.sunbirdrc.service.MailService;
import dev.sunbirdrc.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.sql.SQLException;
import java.util.List;

@RestController
@RequestMapping(path = "/api/v1")
@Slf4j
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private MailService mailService;

    @PostMapping("/login")
    public ResponseEntity<UserTokenDetailsDTO> loginUser(@Valid @RequestBody UserLoginDTO userLoginDTO) {
        log.info("RC UM controller | method - login - start");
        UserTokenDetailsDTO keycloakTokenDetailsDTO = userService.loginAndGenerateKeycloakToken(userLoginDTO);
        log.info("RC UM controller | method - login - end | response - {}", keycloakTokenDetailsDTO);
        return new ResponseEntity<>(keycloakTokenDetailsDTO, HttpStatus.OK);
    }

    @GetMapping("/logout/{userId}")
    public ResponseEntity<String> logoutUser(@Valid @NotNull @NotEmpty @PathVariable String userId) {
        log.info("RC UM controller | method - logout - start - userId - {}", userId);
        userService.logout(userId);
        log.info("RC UM controller | method - logout - end | response - {}", "success");
        return new ResponseEntity<>("Success", HttpStatus.OK);
    }

    @PostMapping("/registerUser")
    public ResponseEntity<String> registerUser(@Valid @RequestBody UserDetailsDTO userDTO) {
        log.info("RC UM controller | method - register user - start");
        boolean status = userService.registerUser(userDTO);
        log.info("RC UM controller | method - register user - end | response - {}", status);
        if (status) {
            return new ResponseEntity<>("Successfully added user", HttpStatus.CREATED);
        }else {
            return new ResponseEntity<>("Unable to create user", HttpStatus.FAILED_DEPENDENCY);
        }
    }

    @PostMapping("/verifyAndUpdate/otp")
    public ResponseEntity<String> verifyUserMailOTP(@Valid @RequestBody UserOtpDTO userOtpDTO) {
        boolean verified = false;
        try {
            log.info("RC UM controller | method - verify OTP - start");
            verified = userService.verifyMailOTP(userOtpDTO);
            log.info("RC UM controller | method - verify OTP - end | response - {}", verified);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        if (verified) {
            return new ResponseEntity<>("Successfully verified user", HttpStatus.CREATED);
        }else {
            return new ResponseEntity<>("Unable to verify", HttpStatus.FAILED_DEPENDENCY);
        }
    }

    @PostMapping("/admin/generateOtp")
    public ResponseEntity<String> generateAdminOtp(@Valid @RequestBody AdminDTO adminDTO) {
        try {
            log.info("RC UM controller | method - generate OTP - start");
            userService.generateAdminOtp(adminDTO);
            log.info("RC UM controller | method - generate OTP - end | response - {}", HttpStatus.OK.getReasonPhrase());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new ResponseEntity<>("Sending OTP to user mail", HttpStatus.OK);
    }

    @PostMapping("/admin/login")
    public ResponseEntity<UserTokenDetailsDTO> loginAdminUser(@Valid @RequestBody AdminLoginDTO adminLoginDTO) {
        UserTokenDetailsDTO tokenDetailsDTO = null;
        try {
            log.info("RC UM controller | method - admin login - start");
            tokenDetailsDTO = userService.getAdminTokenByOtp(adminLoginDTO);
            log.info("RC UM controller | method - admin login - end | response - {}", tokenDetailsDTO);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new ResponseEntity<>(tokenDetailsDTO, HttpStatus.OK);
    }

    @GetMapping(path = "/keycloak")
    public ResponseEntity<String> getUser(){


        return new ResponseEntity<>("Role base access", HttpStatus.OK);
    }

    @PostMapping("/keycloak/createBulkUser")
    public ResponseEntity<BulkCustomUserResponseDTO> createBulkUser(@Valid @RequestBody List<CustomUserDTO> customUserDTOList) {
        BulkCustomUserResponseDTO bulkCustomUserResponseDTO = userService.addBulkUser(customUserDTOList);

        return new ResponseEntity<>(bulkCustomUserResponseDTO, HttpStatus.CREATED);
    }

    @PostMapping("/keycloak/pushBulkUserBG")
    public ResponseEntity<String> pushBulkUserBG(@Valid @RequestBody BulkUserCreationDTO bulkUserCreationDTO) {
        userService.pushBulkUserBG(bulkUserCreationDTO);

        return new ResponseEntity<>("{\"success\":true,\"message\":\"Aknowledged\"}", HttpStatus.OK);
    }

    @GetMapping("/keycloak/bulkUserStatus")
    public ResponseEntity<BulkCustomUserResponseDTO> bulkUserStatus() {
        BulkCustomUserResponseDTO bulkCustomUserResponseDTO = userService.getBulkUserStatus();

        return new ResponseEntity<>(bulkCustomUserResponseDTO, HttpStatus.CREATED);
    }


    @PostMapping("/user/generateOtp")
    public ResponseEntity<String> generateUserOtp(@Valid @RequestBody CustomUsernameDTO customUsernameDTO) {
        log.info("RC UM controller | method - user generate OTP - start");
        userService.generateCustomUserOtp(customUsernameDTO);
        log.info("RC UM controller | method - user generate OTP - end");

        return new ResponseEntity<>("Sending OTP to user mail", HttpStatus.OK);
    }

    @PostMapping("/user/login")
    public ResponseEntity<UserTokenDetailsDTO> loginCustomUser(@Valid @RequestBody CustomUserLoginDTO customUserLoginDTO) {
        UserTokenDetailsDTO tokenDetailsDTO = null;
        try {
            log.info("RC UM controller | method - user login - start");
            tokenDetailsDTO = userService.getCustomUserTokenByOtp(customUserLoginDTO);
            log.info("RC UM controller | method - user login - end | response - {}", tokenDetailsDTO);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new ResponseEntity<>(tokenDetailsDTO, HttpStatus.OK);
    }

    @PostMapping(path = "/keycloak/user/delete")
    public ResponseEntity<String> deleteUser(@Valid @RequestBody List<CustomUserDeleteDTO> customUserDeleteDTOList){
        log.info("RC UM controller | method - keycloak delete user - start");
        userService.deleteBulkUSer(customUserDeleteDTOList);
        log.info("RC UM controller | method - keycloak delete user - end");

        return new ResponseEntity<>("Successfully delete the user", HttpStatus.OK);
    }

    @PostMapping("/keycloak/user/update")
    public ResponseEntity<String> updateUser(@Valid @RequestBody CustomUserUpdateDTO customUserUpdateDTO) {
        log.info("RC UM controller | method - update user - start");
        userService.updateUser(customUserUpdateDTO);
        log.info("RC UM controller | method - update user - end");

        return new ResponseEntity<>("Successfully updated user", HttpStatus.OK);
    }

    @PostMapping("/keycloak/user/create")
    public ResponseEntity<CustomUserResponseDTO> createCustomUser(@Valid @RequestBody CustomUserDTO customUserDTO) {
        log.info("RC UM controller | method - keycloak user create - start");
        CustomUserResponseDTO customUserResponseDTO = userService.createCustomUser(customUserDTO);
        log.info("RC UM controller | method - keycloak user create - end | response - {}", customUserResponseDTO);

        return new ResponseEntity<>(customUserResponseDTO, HttpStatus.OK);
    }

    @PostMapping("/keycloak/persist/userCredential")
    public ResponseEntity<String> persistUserCredential(@RequestBody CustomUserDTO customUserDTO) {
        try {
            log.info("RC UM controller | method - keycloak persist user credentials - start");
            userService.persistUserDetailsWithCredentials(customUserDTO);
            log.info("RC UM controller | method - keycloak persist user credentials - end");
        } catch (Exception e) {
            return new ResponseEntity<>("Failed to persist", HttpStatus.EXPECTATION_FAILED);
        }

        return new ResponseEntity<>("Persist successfully", HttpStatus.OK);
    }

    @PostMapping("/keycloak/mail/sendOTP")
    public ResponseEntity<String> sendOTPMail(@RequestBody UserDetails userDetails) {
        try {
            log.info("RC UM controller | method - keycloak OTP mail - start");
            mailService.sendOtpMail(userDetails);
            log.info("RC UM controller | method - keycloak OTP mail - end");
        } catch (Exception e) {
            return new ResponseEntity<>("Failed to persist", HttpStatus.EXPECTATION_FAILED);
        }

        return new ResponseEntity<>("Persist successfully", HttpStatus.OK);
    }

    @PostMapping("/keycloak/mail/userCreate")
    public ResponseEntity<String> sendUserCreationMail(@RequestBody CustomUserDTO customUserDTO) {
        try {
            log.info("RC UM controller | method - keycloak user create mail - start");
            mailService.sendUserCreationNotification(customUserDTO);
            log.info("RC UM controller | method - keycloak user create mail - end");
        } catch (Exception e) {
            return new ResponseEntity<>("Failed to persist", HttpStatus.EXPECTATION_FAILED);
        }

        return new ResponseEntity<>("Persist successfully", HttpStatus.OK);
    }

    @PostMapping(value = "/user/attribute", produces = "application/json")
    public List getUserByAttribute(@RequestBody JsonNode body) throws SQLException {
        return userService.getUserByAttribute(body);
    }

    @PostMapping("/user/exist")
    public ResponseEntity<Boolean> isUserExistByUsername(@Valid @RequestBody CustomUsernameDTO customUsernameDTO) {
        log.info("RC UM controller | method - user exists - start");
        Boolean isUserExist = userService.isUserExist(customUsernameDTO.getUsername());
        log.info("RC UM controller | method - user exists - end | response - {}", isUserExist);

        return new ResponseEntity<>(isUserExist, HttpStatus.OK);
    }

}
