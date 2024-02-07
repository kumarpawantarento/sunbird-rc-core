package dev.sunbirdrc.exception;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class InvalidInputDataException extends CustomException {

    public InvalidInputDataException(String message) {
        super(message);
    }
}
