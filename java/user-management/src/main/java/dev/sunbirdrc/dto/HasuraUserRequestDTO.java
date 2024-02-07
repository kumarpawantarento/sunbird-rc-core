package dev.sunbirdrc.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class HasuraUserRequestDTO {
    private List<RegulatorDTO> regulators;
    private List<AssessorDTO> assessors;
}
