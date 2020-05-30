package com.csys.medicaloffice.entities;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class PolyclinicHospital implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String adresse;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date dateInsert;

    @OneToMany(mappedBy = "PolyclinicHospital")
    private Collection<HospitalisationLettre> hospitalisationLettres;

}
