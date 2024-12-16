package hb.springsecurityjwt.Models;

import jakarta.persistence.*;

import lombok.*;
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Role extends AbstractEntity{


    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;
}

