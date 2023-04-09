package com.akash.jwtauth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthRequest {
    private final String userName;
    private final String password;
}
