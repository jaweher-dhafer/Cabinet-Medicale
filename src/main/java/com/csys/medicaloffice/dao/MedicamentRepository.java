package com.csys.medicaloffice.dao;

import com.csys.medicaloffice.entities.Medicament;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin("*")
@RepositoryRestResource
public interface MedicamentRepository extends JpaRepository<Medicament, Long> {

    @RestResource(path = "/byDateInsertPage")
    @Query("Select M from Medicament M ORDER BY M.dateInsert desc ")
    Page<Medicament> findMedicaments(Pageable pageable);
}
