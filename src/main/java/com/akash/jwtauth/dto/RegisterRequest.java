package com.akash.jwtauth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public final class RegisterRequest {
    private final String firstName;
    private final String lastName;
    private final String email;
    private final String password;
}
