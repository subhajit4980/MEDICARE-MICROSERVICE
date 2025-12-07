//package com.medicare.Auth_Service.Config;
//
//import io.github.cdimascio.dotenv.Dotenv;
//import jakarta.annotation.PostConstruct;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.stereotype.Component;
//
////@Configuration
////public class EnvLoader {
////
////    static {
////        // 👇 Load .env file from a custom external directory
////        Dotenv dotenv = Dotenv.configure()
////                .directory("Medicare-microservice\\.env") // external location
////                .filename(".env")
////                .load();
////
////        dotenv.entries().forEach(e ->
////                System.setProperty(e.getKey(), e.getValue())
////        );
////    }
////}
//
//@Component
//public class EnvLoader {
//
//    @PostConstruct
//    public void loadEnv() {
//        Dotenv dotenv = Dotenv.configure()
//                .directory("E:/SPRING BOOT ALL/PROJECTS/Medicare-microservice/") // external location
//                .filename(".env")
//                .ignoreIfMalformed()
//                .ignoreIfMissing()
//                .load();
//        dotenv.entries().forEach(e ->
//                {
//                    System.setProperty(e.getKey(), e.getValue());
//                    System.out.println(e.getKey() +" "+ e.getValue());
//                }
//
//        );
//
//        System.out.println("✅ Loaded .env variables for Auth-Service");
//    }
//}