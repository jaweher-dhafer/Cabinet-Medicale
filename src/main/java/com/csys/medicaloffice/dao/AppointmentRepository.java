package com.csys.medicaloffice.dao;

import com.csys.medicaloffice.entities.Appointment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.List;


@CrossOrigin("*")
@RepositoryRestResource
public interface AppointmentRepository extends JpaRepository<Appointment, Long> {

    @RestResource(path = "/byDate")
    @Query("Select A from Appointment A WHERE DATE_FORMAT(A.date ,'%y-%m-%d') = DATE_FORMAT(:date ,'%y-%m-%d')")
    List<Appointment> getAppointmentPlanifie(@Param("date") String date);

}

