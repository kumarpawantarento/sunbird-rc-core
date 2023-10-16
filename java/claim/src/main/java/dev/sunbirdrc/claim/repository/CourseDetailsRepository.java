package dev.sunbirdrc.claim.repository;

import dev.sunbirdrc.claim.entity.CourseDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CourseDetailsRepository extends JpaRepository<CourseDetails, Long> {
    List<CourseDetails> findByCouncilNameAndCourseNameAndActivityName(String councilName, String courseName, String activityName);

    @Query("SELECT cd.courseKey FROM CourseDetails cd WHERE cd.councilName = :councilName " +
            "and cd.courseName = :courseName and cd.activityName = :activityName " +
            "and category = :category and cd.status = true")
    Optional<String> findCourseKeyForGeneralCategory(String councilName, String courseName, String activityName, String category);
    @Query("SELECT cd.courseKey FROM CourseDetails cd WHERE cd.councilName = :councilName " +
            "and category = :category and cd.status = true")
    Optional<String> findCourseKeyByCouncilAndCategory(String councilName, String category);
}

