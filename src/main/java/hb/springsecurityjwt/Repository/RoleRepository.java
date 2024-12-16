package hb.springsecurityjwt.Repository;

import hb.springsecurityjwt.Models.ERole;
import hb.springsecurityjwt.Models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}

