package com.csys.medicaloffice.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Collection;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Confer extends Person implements Serializable {
    private String adresse;
    private String specialite;
    @OneToMany(mappedBy = "Confer")
    private Collection<LetterToConfer> letterToConfers;
}
