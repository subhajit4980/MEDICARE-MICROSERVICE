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

# Copy the JAR from the builder stage
# Replace <Service-JAR-Name>.jar with your actual JAR name
COPY --from=builder target/*.jar Api-Gateway.jar

EXPOSE 8765

# Run the JAR
ENTRYPOINT ["java", "-jar", "Api-Gateway.jar"]
