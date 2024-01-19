package dev.sunbirdrc.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Data
@Builder
public class RegulatorDTO {
    private String phonenumber;
    private String user_id;
    private String full_name;
    private String email;
    private String fname;
    private String lname;
    private String role;
    private String workingstatus;
}
