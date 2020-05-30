package com.csys.medicaloffice.dao;

import com.csys.medicaloffice.entities.LetterToConfer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin("*")
@RepositoryRestResource
public interface LetterToConferRepository extends JpaRepository<LetterToConfer, Long> {
}
