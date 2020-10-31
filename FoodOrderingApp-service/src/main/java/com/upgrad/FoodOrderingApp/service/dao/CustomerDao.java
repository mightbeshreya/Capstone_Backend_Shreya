package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;

@Repository
public class CustomerDao {
    @PersistenceContext
    private EntityManager entityManager;

    public CustomerEntity createUser(CustomerEntity customerEntity) {
        entityManager.persist(customerEntity);
        return customerEntity;
    }

    public boolean doesUserExist(final String contactNumber) {
        try{
            CustomerEntity singleResult = entityManager.createNamedQuery(
                    "customerByContactNumber", CustomerEntity.class)
                    .setParameter("contactNumber", contactNumber).getSingleResult();
            return true;
        }catch(NoResultException nre) {
            return false;
        }
    }

    public CustomerEntity getUserByContactNumber(String contactNumber) {
        try{
            CustomerEntity singleResult = entityManager.createNamedQuery(
                    "customerByContactNumber", CustomerEntity.class)
                    .setParameter("contactNumber", contactNumber).getSingleResult();
            return singleResult;
        }catch(NoResultException nre) {
            return null;
        }
    }

    public CustomerAuthTokenEntity createAuthToken(final CustomerAuthTokenEntity customerAuthTokenEntity) {
        entityManager.persist(customerAuthTokenEntity);
        return customerAuthTokenEntity;
    }

    public CustomerAuthTokenEntity getUserAuthToken(final String accessToken) {
        try {
            return entityManager.createNamedQuery("customerAuthTokenByAccessToken", CustomerAuthTokenEntity.class).setParameter("accessToken", accessToken).getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    public void updateCustomerLogoutAt(final CustomerAuthTokenEntity customerAuthToken) {
        entityManager.merge(customerAuthToken);
    }

    public CustomerEntity updateCustomerName(CustomerEntity updateCustomer) {
        CustomerEntity updatedCustomer = entityManager.merge(updateCustomer);
        return updatedCustomer;
    }
}
