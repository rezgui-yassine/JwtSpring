package com.rezguiyassine.springsecurityProject.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserReposotiry extends JpaRepository<User, Integer> {
  Optional <User> findByEmail(String email);
}
