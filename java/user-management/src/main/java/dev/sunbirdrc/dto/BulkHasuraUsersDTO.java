package dev.sunbirdrc.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@Data
@Builder
@NoArgsConstructor
public class BulkHasuraUsersDTO {
    private List<CustomUserDTO> exitedUsers;
    private List<CustomUserDTO> newUsers;
}
