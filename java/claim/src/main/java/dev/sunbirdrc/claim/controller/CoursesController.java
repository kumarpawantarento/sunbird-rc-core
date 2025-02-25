package dev.sunbirdrc.claim.controller;

import dev.sunbirdrc.claim.entity.Courses;
import dev.sunbirdrc.claim.service.CoursesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/courses")
public class CoursesController {

    private CoursesService coursesService;

    @Autowired
    public CoursesController(CoursesService coursesService) {
        this.coursesService = coursesService;
    }

    @GetMapping("/all")
    public ResponseEntity<List<Courses>> getAllCourses() {
        List<Courses> courses = coursesService.getAllCourses();
        return ResponseEntity.ok(courses);
    }

    @GetMapping("/")
    public ResponseEntity<List<String>> getAllCourseName() {
        List<Courses> courses = coursesService.getAllCourses();
        List<String> courseName = new ArrayList<>();
        for (Courses course:courses) {
            courseName.add(course.getCourseName());
        }
        return ResponseEntity.ok(courseName);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Courses> getCourseById(@PathVariable Long id) {
        Optional<Courses> course = coursesService.getCourseById(id);

        if (course.isPresent()) {
            return ResponseEntity.ok(course.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/category")
    public ResponseEntity<Courses> getCourseByName(@RequestParam(value = "category", required = false) String category) {
        Optional<Courses> course = coursesService.getCourseByCourse(category);

        if (course.isPresent()) {
            return ResponseEntity.ok(course.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/diploma")
    public ResponseEntity<List<String>> getCourseByCategory(@RequestParam(value = "category", required = false) String category) {
        List<String> course = coursesService.getCourseByCategory(category);
            return ResponseEntity.ok(course);
    }

    @GetMapping("/course-template-key/{courseName}")
    public ResponseEntity<String> getCourseShortName(@PathVariable String courseName) {
        courseName = courseName.replace("%20"," ");
        String course = coursesService.getCourseTemplateKey(courseName);
        return ResponseEntity.ok(course);
    }

    @GetMapping("/course-template-key/{courseName}/{requestType}")
    public ResponseEntity<String> getCourseShortNameRequestType(@PathVariable String courseName, @PathVariable String getCourseTemplateKey) {
        courseName = courseName.replace("%20"," ");
        String course = coursesService.getCourseTemplateKey(courseName, getCourseTemplateKey);
        return ResponseEntity.ok(course);
    }

    @PostMapping
    public ResponseEntity<Courses> createCourse(@RequestBody Courses course) {
        Courses savedCourse = coursesService.createCourse(course);
        return ResponseEntity.ok(savedCourse);
    }
}
