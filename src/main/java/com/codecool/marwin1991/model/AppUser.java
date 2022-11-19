package com.codecool.marwin1991.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Data
public class AppUser {


  @Id
  @GeneratedValue(generator = "uuid")
  @GenericGenerator(name = "uuid", strategy = "uuid2")
  private String id;
  private String name;
  private String email;
  private String imageurl;
  private Boolean emailVerified = false;
  @JsonIgnore private String password = null;
  private AuthProvider provider;
  private String providerId;
}
