package dev.sunbirdrc.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Data
@Builder
public class AssessorDTO {
    private String phonenumber;
    private String user_id;
    private String name;
    private String email;
    private String fname;
    private String lname;
    private String role;
    private String code;
}
