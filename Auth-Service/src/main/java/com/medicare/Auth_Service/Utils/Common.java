package com.medicare.Auth_Service.Utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Common {
    public static List<String> validatePassword(String password) {
        List<String> validationTypes = new ArrayList<>();
        if (!password.matches(".*\\d.*")) validationTypes.add("add at least one Digit");
        if (!password.matches(".*[a-z].*")) validationTypes.add("add at least one Lowercase letter");
        if (!password.matches(".*[A-Z].*")) validationTypes.add("add at least one Uppercase letter");
        if (!password.matches(".*[@#$%^&+=!].*")) validationTypes.add("add at least one Special character");
        if (!password.matches(".{8,}")) validationTypes.add( "Password length must be >= 8");
        if (password.matches(".*\\s.*")) validationTypes.add( "Password must not contain spaces");
        return validationTypes;
    }

    // Generate OTP
    public static String generateOTP() {
        // Use SecureRandom for generating random numbers
        SecureRandom secureRandom = new SecureRandom();
        // Generate a random byte array
        byte[] randomBytes = new byte[6];
        secureRandom.nextBytes(randomBytes);
        // Encode the byte array to Base64
        String otp = Base64.getEncoder().encodeToString(randomBytes);
        // Trim the OTP to the desired length and remove special characters
        otp = otp.replaceAll("[^a-zA-Z0-9]", "").substring(0, 6);
        return otp;
    }
}
