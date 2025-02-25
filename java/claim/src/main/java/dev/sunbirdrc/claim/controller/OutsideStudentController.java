package dev.sunbirdrc.claim.controller;

import dev.sunbirdrc.claim.model.ClaimStatus;
import dev.sunbirdrc.claim.service.ClaimService;
import dev.sunbirdrc.claim.service.StudentForeignVerificationService;
import dev.sunbirdrc.claim.service.StudentGoodStandingService;
import dev.sunbirdrc.claim.service.StudentOutsideUpService;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class OutsideStudentController {

    @Autowired
    private StudentForeignVerificationService foreignVerificationService;

    @Autowired
    private StudentOutsideUpService studentOutsideUpService;

    @Autowired
    private StudentGoodStandingService studentGoodStandingService;

    @Autowired
    private ClaimService claimService;

    @GetMapping("/generate/foreignStudentDetails/{id}")
    public ResponseEntity<String> getForeignStudentVerificationDetail(@PathVariable String id) {
        String template = foreignVerificationService.generateVerificationLinkContent(id);

        if (!StringUtils.isEmpty(template)) {
            return new ResponseEntity<>(template, HttpStatus.OK);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/generate/outsideStudentDetails/{id}")
    public ResponseEntity<String> getOutsideStudentVerificationDetail(@PathVariable String id) {
        String template = studentOutsideUpService.generateVerificationLinkContent(id);

        if (!StringUtils.isEmpty(template)) {
            return new ResponseEntity<>(template, HttpStatus.OK);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/generate/studentGoodStandingDetails/{id}")
    public ResponseEntity<String> generateStudentGoodStandingDetails(@PathVariable String id) {
        String template = studentGoodStandingService.generateVerificationLinkContent(id);

        if (!StringUtils.isEmpty(template)) {
            return new ResponseEntity<>(template, HttpStatus.OK);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/outsideStudent/verify/{id}/{status}")
    public ResponseEntity<String> verifyOutsideStudentClaim(@PathVariable String id,
                                                                   @PathVariable ClaimStatus status) {

        claimService.updateOutsideStudentStatus(id, status);

        return new ResponseEntity<>("Outside/Foreign/GoodStanding student verification updated", HttpStatus.OK);
    }

    @GetMapping("/update/internal/followUp/{id}/{status}")
    public ResponseEntity<String> updateInternalFollowUpStatus(@PathVariable String id,
                                                                   @PathVariable String status) {

        claimService.updateInternalFollowUpStatus(id, status);

        return new ResponseEntity<>("Follow up status updated successfully", HttpStatus.OK);
    }

    @GetMapping("/generateVerifyLink/{entityType}/{entityId}")
    public ResponseEntity<String> generateVerifyLink(@PathVariable String entityType, @PathVariable String entityId) {

        String verifyLink = studentOutsideUpService.generateVerifyLinkForForeignOutsideStudent(entityType, entityId);

        if (!StringUtils.isEmpty(verifyLink)) {
            return new ResponseEntity<>(verifyLink, HttpStatus.OK);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
