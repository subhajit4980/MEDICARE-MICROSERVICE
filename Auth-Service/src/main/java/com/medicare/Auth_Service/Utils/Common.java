package com.medicare.Auth_Service.Utils;

import java.util.ArrayList;
import java.util.List;

public class Common {
    public static List<String> validatePassword(String password) {
        List<String> missingCharTypes = new ArrayList<>();
        if (!password.matches(".*\\d.*")) missingCharTypes.add("Digit");
        if (!password.matches(".*[a-z].*")) missingCharTypes.add("Lowercase letter");
        if (!password.matches(".*[A-Z].*")) missingCharTypes.add("Uppercase letter");
        if (!password.matches(".*[@#$%^&+=!].*")) missingCharTypes.add("Special character");
        return missingCharTypes;
    }
}
