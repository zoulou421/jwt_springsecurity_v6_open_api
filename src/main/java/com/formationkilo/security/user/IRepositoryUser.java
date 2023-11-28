package com.formationkilo.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IRepositoryUser extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String email);
}
