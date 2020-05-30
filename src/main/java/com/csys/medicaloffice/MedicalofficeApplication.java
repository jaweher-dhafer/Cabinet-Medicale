package com.csys.medicaloffice;

import com.csys.medicaloffice.entities.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

@SpringBootApplication
public class MedicalofficeApplication implements CommandLineRunner {

    @Autowired
    private RepositoryRestConfiguration repositoryRestConfiguration;

    public static void main(String[] args) {
        SpringApplication.run(MedicalofficeApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        repositoryRestConfiguration.exposeIdsFor(Appointment.class);
        repositoryRestConfiguration.exposeIdsFor(Confer.class);
        repositoryRestConfiguration.exposeIdsFor(Consultation.class);
        repositoryRestConfiguration.exposeIdsFor(HospitalisationLettre.class);
        repositoryRestConfiguration.exposeIdsFor(LetterToConfer.class);
        repositoryRestConfiguration.exposeIdsFor(LigneOrdonnance.class);
        repositoryRestConfiguration.exposeIdsFor(MedicalCertificate.class);
        repositoryRestConfiguration.exposeIdsFor(Medicament.class);
        repositoryRestConfiguration.exposeIdsFor(Ordonnance.class);
        repositoryRestConfiguration.exposeIdsFor(Patient.class);
        repositoryRestConfiguration.exposeIdsFor(PolyclinicHospital.class);


    }

}
