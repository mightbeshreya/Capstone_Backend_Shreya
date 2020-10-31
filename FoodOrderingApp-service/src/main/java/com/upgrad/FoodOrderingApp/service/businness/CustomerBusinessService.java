package com.upgrad.FoodOrderingApp.service.businness;


import com.upgrad.FoodOrderingApp.service.common.GenericErrorCode;
import com.upgrad.FoodOrderingApp.service.common.UnexpectedException;
import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class CustomerBusinessService {
    @Autowired
    private CustomerDao customerDao;

    @Autowired
    private PasswordCryptographyProvider passwordCryptographyProvider;

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity signup(CustomerEntity customerEntity) throws SignUpRestrictedException {
        System.out.println("Inside Signup");

        if(customerEntity.getContactNumber() == null|| customerEntity.getEmail() == null|| customerEntity.getFirstName() == null
        || customerEntity.getPassword() == null) {
            throw new SignUpRestrictedException("SGR-005", "Except last name all fields should be filled");
        }

        if(customerDao.doesUserExist(customerEntity.getContactNumber())) {
            throw new SignUpRestrictedException("SGR-001", "This contact number is already registered! Try other contact number.");
        }

        if(!validEmail(customerEntity.getEmail())) {
            throw new SignUpRestrictedException("SGR-002", "Invalid email-id format!");
        }

        if(!validPhoneNumber(customerEntity.getContactNumber())) {
            throw new SignUpRestrictedException("SGR-003", "Invalid contact number!");
        }

        if(!checkForPasswordStrength(customerEntity.getPassword())) {
            throw new SignUpRestrictedException("SGR-004", "Weak password!");
        }

        String[] encryptedText = passwordCryptographyProvider.encrypt(customerEntity.getPassword());
        customerEntity.setSalt(encryptedText[0]);
        customerEntity.setPassword(encryptedText[1]);

        CustomerEntity signUpCustomer = customerDao.createUser(customerEntity);

        return signUpCustomer;
    }

    private boolean validEmail(String customerEmail) {
        String regex = "^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$";
        boolean result = customerEmail.matches(regex);
        return result;
    }

    private boolean validPhoneNumber (String phoneNumber) {
        String regex = "^[0-9]{10}$";
        boolean result = phoneNumber.matches(regex);
        return result;
    }

    private boolean checkForPasswordStrength (String pass) {
        String regex = "^(?=.*[0-9])(?=.*[A-Z])(?=.*[@#$%^&-+=()])(?=\\\\S+$).{8,}$";
        Pattern pattern = Pattern.compile(regex);
        if (pass == null) {
            return false;
        }
        Matcher m = pattern.matcher(pass);
        return m.matches();
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerAuthTokenEntity login(final String contactNumber, final String password) throws AuthenticationFailedException {
        CustomerEntity customerEntity = customerDao.getUserByContactNumber(contactNumber);
        try {
            if(customerEntity==null) {
                throw new AuthenticationFailedException("ATH-001", "This contact number has not been registered!");
            }
            final String encryptedPassword = passwordCryptographyProvider.encrypt(password, customerEntity.getSalt());
            if (encryptedPassword.equals(customerEntity.getPassword())) {
                JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(encryptedPassword);
                CustomerAuthTokenEntity customerAuthTokenEntity = new CustomerAuthTokenEntity();

                final ZonedDateTime now = ZonedDateTime.now();
                final ZonedDateTime expiresAt = now.plusHours(8);

                customerAuthTokenEntity.setUuid(UUID.randomUUID().toString());
                customerAuthTokenEntity.setCustomer(customerEntity);
                customerAuthTokenEntity.setAccessToken(jwtTokenProvider.generateToken(customerEntity.getUuid(), now, expiresAt));
                customerAuthTokenEntity.setExpiresAt(expiresAt);
                customerAuthTokenEntity.setLoginAt(now);

                customerDao.createAuthToken(customerAuthTokenEntity);

                return customerAuthTokenEntity;
            } else {
                throw new AuthenticationFailedException("ATH-002", "Invalid Credentials");
            }
        }catch (Exception ex) {
            GenericErrorCode genericErrorCode = GenericErrorCode.GEN_001;
            throw new UnexpectedException(genericErrorCode, ex);
        }
    }

    public void authFormatCheck (final String authorization) throws AuthenticationFailedException{
        try {
            byte[] decoded = Base64.getDecoder().decode(authorization.split(" ")[1]);
            String decodedText = new String(decoded);
            String[] decodedArray = decodedText.split(":");
            if(authorization!=null && authorization.startsWith("Basic ") && decodedArray.length==2) {
                return;
            }else {
                throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
            }
        }catch(Exception e) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerAuthTokenEntity logout(final String accessToken) throws AuthorizationFailedException {
        CustomerAuthTokenEntity customerAuthToken = customerDao.getUserAuthToken(accessToken);
        //if the access token doesnt exist in the database it will throw an error with below message
        //else if the access token exists in the database the logout time will be updated and persisted in the database
        if (customerAuthToken == null) {
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }
        else {
            if(customerAuthToken.getLogoutAt()!=null) {
                throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
            }
            final ZonedDateTime now = ZonedDateTime.now();
            if(customerAuthToken.getExpiresAt().isBefore(now) || customerAuthToken.getExpiresAt().isEqual(now)){
                throw new AuthorizationFailedException("ATHR-003", "Your session is expired. Log in again to access this endpoint.");
            }
            else {
                customerAuthToken.setLogoutAt(now);
                customerDao.updateCustomerLogoutAt(customerAuthToken);
                return customerAuthToken;
            }
        }
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity updateCustomer(final String accessToken, final String firstname, final String lastname)
            throws AuthorizationFailedException, UpdateCustomerException {
        if(firstname==null||firstname=="") {
            throw new UpdateCustomerException("UCR-002", "First name field should not be empty");
        }
        CustomerAuthTokenEntity customerAuthToken = customerDao.getUserAuthToken(accessToken);
        if (customerAuthToken == null) {
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else {
            if(customerAuthToken.getLogoutAt()!=null) {
                throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
            }
            final ZonedDateTime now = ZonedDateTime.now();
            if(customerAuthToken.getExpiresAt().isBefore(now) || customerAuthToken.getExpiresAt().isEqual(now)) {
                throw new AuthorizationFailedException("ATHR-003", "Your session is expired. Log in again to access this endpoint.");
            }
            CustomerEntity customerEntity = customerAuthToken.getCustomer();
            customerEntity.setFirstName(firstname);
            customerEntity.setLastName(lastname);
            CustomerEntity updatedCustomer = customerDao.updateCustomerName(customerEntity);
            return updatedCustomer;
        }
    }
}
