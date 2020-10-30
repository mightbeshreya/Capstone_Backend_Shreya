package com.upgrad.FoodOrderingApp.service.businness;


import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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
}
