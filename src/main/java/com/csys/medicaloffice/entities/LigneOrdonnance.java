package com.csys.medicaloffice.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LigneOrdonnance {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private float dosage;
    private int nbprise;
    private String periode;
    @ManyToOne
    private Ordonnance Ordonnance;
    @ManyToOne
    private Medicament Medicament;

}
