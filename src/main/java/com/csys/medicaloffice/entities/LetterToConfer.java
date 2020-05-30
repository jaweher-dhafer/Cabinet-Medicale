package com.csys.medicaloffice.entities;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LetterToConfer implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String objet;
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date dateInsert;
    private String description;
    @ManyToOne
    private Patient patient;
    @ManyToOne
    private Confer Confer;


}
