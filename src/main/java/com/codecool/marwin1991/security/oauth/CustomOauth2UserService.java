package com.codecool.marwin1991.security.oauth;

import com.codecool.marwin1991.exception.OAuth2AuthenticationProcessingException;
import com.codecool.marwin1991.model.AppUser;
import com.codecool.marwin1991.model.AuthProvider;
import com.codecool.marwin1991.repository.UserRepository;
import com.codecool.marwin1991.security.UserPrincipal;
import com.codecool.marwin1991.security.oauth.user.OAuth2UserInfo;
import com.codecool.marwin1991.security.oauth.user.OAuth2UserInfoFactory;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
@AllArgsConstructor
public class CustomOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception e){
            throw new InternalAuthenticationServiceException(e.getMessage(), e.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.get(userRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());

        if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())){
            throw new OAuth2AuthenticationProcessingException("Email not found from provider");
        }

        Optional<AppUser> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        AppUser appUser;
        if(userOptional.isPresent()){
            appUser = userOptional.get();
            //TODO check provider if equals
            appUser = update(appUser, oAuth2UserInfo);
        } else {
            appUser = register(userRequest, oAuth2UserInfo);
        }

        return UserPrincipal.create(appUser, oAuth2User.getAttributes());
    }

    private AppUser register(OAuth2UserRequest userRequest, OAuth2UserInfo oAuth2UserInfo) {
        AppUser appUser = new AppUser();

        appUser.setProvider(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId()));
        appUser.setProviderId(oAuth2UserInfo.getId());
        appUser.setName(oAuth2UserInfo.getName());
        appUser.setEmail(oAuth2UserInfo.getEmail());
        appUser.setImageurl(oAuth2UserInfo.getImageUrl());

        return userRepository.save(appUser);
    }

    private AppUser update(AppUser appUser, OAuth2UserInfo oAuth2UserInfo) {
      appUser.setName(oAuth2UserInfo.getName());
      appUser.setImageurl(oAuth2UserInfo.getImageUrl());
         return userRepository.save(appUser);
    }
}
