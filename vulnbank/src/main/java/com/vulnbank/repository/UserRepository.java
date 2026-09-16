package com.vulnbank.repository;

import com.vulnbank.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);

    /**
     * A03:2021 Injection.
     * This query is built with raw string concatenation inside AuthController
     * and executed via nativeQuery here - classic SQL injection target.
     * Try username: admin' -- in the login form and inspect the request in Burp.
     */
    @Query(value = "SELECT * FROM users WHERE username = ?1 AND password = ?2", nativeQuery = true)
    java.util.List<User> rawLogin(String rawUsernameClause, String password);
}
