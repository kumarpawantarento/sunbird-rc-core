package dev.sunbirdrc.claim.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CourseDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "councilName")
    private String councilName;

    @Column(name = "courseName")
    private String courseName;

    @Column(name = "activityName")
    private String activityName;

    @Column(name = "isGoodStanding")
    private Boolean goodStanding;

    @Column(name = "isForeignVerification")
    private Boolean foreignVerification;

    @Column(name = "status")
    private Boolean status;

    @Column(name = "courseKey")
    private String courseKey;
}
