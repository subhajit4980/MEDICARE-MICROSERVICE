# -------------------------------
# 1. Build stage
# -------------------------------
FROM maven:3.9.9-eclipse-temurin-21 AS builder

# Use a volume for Maven dependencies cache
VOLUME /root/.m2

# Copy only pom.xml first to leverage Docker cache
COPY pom.xml .

# Download dependencies only once into the cache
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Package the application
RUN mvn clean package -DskipTests

# -------------------------------
# 2. Run stage
# -------------------------------
FROM openjdk:17-jdk-slim AS runner

WORKDIR /app

RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder target/*.jar Inventory-Service.jar
EXPOSE 8095
ENTRYPOINT ["java", "-jar", "Inventory-Service.jar"]