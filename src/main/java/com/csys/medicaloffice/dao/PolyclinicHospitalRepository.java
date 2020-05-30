package com.csys.medicaloffice.dao;

import com.csys.medicaloffice.entities.PolyclinicHospital;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin("*")
@RepositoryRestResource
public interface PolyclinicHospitalRepository extends JpaRepository<PolyclinicHospital, Long> {

    @RestResource(path = "/byDateInsertPage")
    @Query("Select P from PolyclinicHospital P ORDER BY P.dateInsert desc ")
    Page<PolyclinicHospital> findPolyclinicHospitals(Pageable pageable);
}
