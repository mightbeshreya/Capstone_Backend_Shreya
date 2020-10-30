package com.upgrad.FoodOrderingApp.service.entity;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.time.ZonedDateTime;


@Entity
@Table(name = "customer")
@NamedQueries(
        {
                @NamedQuery(name = "customerByContactNumber", query = "select c from CustomerEntity c where c.contactNumber = :contactNumber")//,
                //@NamedQuery(name = "userByEmail", query = "select u from UserEntity u where u.email =:email"),
                //@NamedQuery(name = "userByUUID", query = "select u from UserEntity u where u.uuid = :uuid"),
                //@NamedQuery(name = "deleteUserById", query = "delete from UserEntity u where u.uuid = :uuid")
        }
)
public class CustomerEntity implements Serializable {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "uuid")
    @NotNull
    @Size(max = 200)
    private String uuid;

    @Column(name = "firstname")
    @NotNull
    @Size(max = 30)
    private String firstName;

    @Column(name = "lastname")
    @Size(max = 30)
    private String lastName;

    @Column(name = "email")
    @NotNull
    @Size(max = 50)
    private String email;

    @Column(name = "password")
    @NotNull
    @Size(max = 255)
    private String password;

    @Column(name = "salt")
    @NotNull
    @Size(max = 200)
    private String salt;

    @Column(name = "contact_number")
    @NotNull
    @Size(max = 30)
    private String contactNumber;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getContactNumber() {
        return contactNumber;
    }

    public void setContactNumber(String contactNumber) {
        this.contactNumber = contactNumber;
    }
}
