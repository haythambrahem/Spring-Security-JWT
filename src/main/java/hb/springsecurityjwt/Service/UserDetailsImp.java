package hb.springsecurityjwt.Service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import hb.springsecurityjwt.Models.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class UserDetailsImp implements UserDetails {

    private static final long serialVersionUID =1L;
    private Long id;
    private String username;
    private String email;
    @JsonIgnore
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public UserDetailsImp(Long id, String username, String email, String password,
                          Collection<? extends GrantedAuthority> authorities ){
        this.id=id;
        this.username=username;
        this.email=email;
        this.password=password;
        this.authorities=authorities;
    }
    public static UserDetailsImp build(User user) {
        List<GrantedAuthority> authorities = getAuthorities(user);
        return createUserDetails(user, authorities);
    }
    private static List<GrantedAuthority> getAuthorities(User user) {
        return user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());
    }
    private static UserDetailsImp createUserDetails(User user, List<GrantedAuthority> authorities) {
        return new UserDetailsImp(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

