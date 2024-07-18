package com.mikiyas.spring_security.Dao;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class UserDao {

        private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        private final List<UserDetails> APPLICATION_USERS = Arrays.asList(
                        new User("mk@gmail.com", passwordEncoder.encode("12345"),
                                        Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))),
                        new User("hk@gmail.com", passwordEncoder.encode("password"),
                                        Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")))

        );

        public UserDetails findUserByEmail(String email) {
                return APPLICATION_USERS.stream().filter(user -> user.getUsername().equals(email)).findFirst()
                                .orElseThrow(() -> new UsernameNotFoundException("No user was found"));
        }

}
