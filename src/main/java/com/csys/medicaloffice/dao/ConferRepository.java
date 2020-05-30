package com.csys.medicaloffice.dao;

import com.csys.medicaloffice.entities.Confer;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin("*")
@RepositoryRestResource
public interface ConferRepository extends JpaRepository<Confer, Long> {

    @RestResource(path = "/byDateInsertPage")
    @Query("Select C from Confer C ORDER BY C.dateInsert desc ")
    Page<Confer> findConfers(Pageable pageable);
}
