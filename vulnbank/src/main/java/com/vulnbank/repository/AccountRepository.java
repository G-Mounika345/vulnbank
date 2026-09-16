package com.vulnbank.repository;

import com.vulnbank.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account, Long> {
    java.util.List<Account> findByOwnerId(Long ownerId);
}
