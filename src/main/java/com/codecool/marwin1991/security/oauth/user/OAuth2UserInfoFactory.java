package com.codecool.marwin1991.security.oauth.user;

import com.codecool.marwin1991.exception.OAuth2AuthenticationProcessingException;
import com.codecool.marwin1991.model.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {

  public static OAuth2UserInfo get(String registrationId, Map<String, Object> attributes) {
    if (AuthProvider.google.name().equalsIgnoreCase(registrationId)) {
      return new GoogleOAuth2UserInfo(attributes);
    } else {
      throw new OAuth2AuthenticationProcessingException(registrationId + " is notr supported");
    }
  }
}
