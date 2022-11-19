package com.codecool.marwin1991.controller;

import com.codecool.marwin1991.exception.ResourceNotFoundException;
import com.codecool.marwin1991.model.AppUser;
import com.codecool.marwin1991.repository.UserRepository;
import com.codecool.marwin1991.security.CurrentUser;
import com.codecool.marwin1991.security.UserPrincipal;
import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/profile")
    //TODO sprawdzić czy ma role user korzystajać z @PreAuthorize
    public AppUser getCurrentUser(@CurrentUser UserPrincipal userPrincipal){

        return  userRepository.findById(userPrincipal.getId())
                .orElseThrow(()-> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }
}
