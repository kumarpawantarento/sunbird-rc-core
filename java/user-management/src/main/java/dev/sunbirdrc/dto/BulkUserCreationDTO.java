package dev.sunbirdrc.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@AllArgsConstructor
@Data
@Builder
public class BulkUserCreationDTO {
    private List<CustomUserDTO> userCreationList;
    private String email;
}
