FROM maven:3.9.9-eclipse-temurin-21 AS builder
VOLUME /root/.m2
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests
FROM openjdk:17-jdk-slim AS runner
WORKDIR /app
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder target/*.jar Service-Registry.jar
EXPOSE 8761
ENTRYPOINT ["java", "-jar", "Service-Registry.jar"]
