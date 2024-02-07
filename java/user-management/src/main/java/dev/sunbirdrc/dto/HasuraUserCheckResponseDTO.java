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
public class HasuraUserCheckResponseDTO {
    private List<HasuraUserIdDTO> regulator;
    private List<HasuraUserIdDTO> assessors;
    private List<HasuraUserIdDTO> institutes;
}
