package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.LoginResponse;
import com.upgrad.FoodOrderingApp.api.model.LogoutResponse;
import com.upgrad.FoodOrderingApp.api.model.SignupCustomerRequest;
import com.upgrad.FoodOrderingApp.api.model.SignupCustomerResponse;
import com.upgrad.FoodOrderingApp.service.businness.CustomerBusinessService;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.UUID;

@RestController
@RequestMapping("/")
@CrossOrigin
public class CustomerController {
    @Autowired
    private CustomerBusinessService customerBusinessService;

    @RequestMapping(method = RequestMethod.POST, path = "/customer/signup", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE )
    public ResponseEntity<SignupCustomerResponse> signup(final SignupCustomerRequest signupCustomerRequest) throws SignUpRestrictedException {
        final CustomerEntity customerEntity = new CustomerEntity();

        customerEntity.setUuid(UUID.randomUUID().toString());
        customerEntity.setContactNumber(signupCustomerRequest.getContactNumber());
        customerEntity.setEmail(signupCustomerRequest.getEmailAddress());
        customerEntity.setFirstName(signupCustomerRequest.getFirstName());
        customerEntity.setLastName(signupCustomerRequest.getLastName());
        customerEntity.setPassword(signupCustomerRequest.getPassword());

        final CustomerEntity createdCustomerEntity = customerBusinessService.signup(customerEntity);

        SignupCustomerResponse customerResponse = new SignupCustomerResponse().id(createdCustomerEntity.getUuid())
                .status("CUSTOMER SUCCESSFULLY REGISTERED");

        return new ResponseEntity<SignupCustomerResponse>(customerResponse, HttpStatus.CREATED);
    }

    @RequestMapping(method = RequestMethod.POST, path = "/customer/login", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LoginResponse> login(@RequestHeader("authorization") final String authorization) throws AuthenticationFailedException {
        customerBusinessService.authFormatCheck(authorization);
        byte[] decoded = Base64.getDecoder().decode(authorization.split(" ")[1]);
        String decodedText = new String(decoded);
        String[] decodedArray = decodedText.split(":");
        CustomerAuthTokenEntity customerAuthTokenEntity = customerBusinessService.login(decodedArray[0], decodedArray[1]);
        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setId(customerAuthTokenEntity.getCustomer().getUuid());
        loginResponse.setMessage("LOGGED IN SUCCESSFULLY");
        HttpHeaders headers = new HttpHeaders();
        headers.add("accessToken", customerAuthTokenEntity.getAccessToken());
        return new ResponseEntity<LoginResponse>(loginResponse, headers, HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.POST, path = "/customer/logout", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LogoutResponse> logout(@RequestHeader("authorization") final String accessToken)
            throws AuthorizationFailedException {
        CustomerAuthTokenEntity customerAuthTokenEntity = new CustomerAuthTokenEntity();
        customerAuthTokenEntity = customerBusinessService.logout(accessToken);
        CustomerEntity customer = customerAuthTokenEntity.getCustomer();
        LogoutResponse authorizedLogoutResponse = new LogoutResponse().id(customer.getUuid()).message("LOGGED OUT SUCCESSFULLY");
        return new ResponseEntity<LogoutResponse>(authorizedLogoutResponse,  HttpStatus.OK);
    }

}
