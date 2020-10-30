package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.SignupCustomerRequest;
import com.upgrad.FoodOrderingApp.api.model.SignupCustomerResponse;
import com.upgrad.FoodOrderingApp.service.businness.CustomerBusinessService;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

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
}
