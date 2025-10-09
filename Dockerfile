FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app
COPY . .
RUN mvn package

FROM gcr.io/distroless/java17-debian11
WORKDIR /app
COPY --from=builder /app/target/obp-oidc-1.0.0-SNAPSHOT.jar /app/obp-oidc-1.0.0-SNAPSHOT.jar
CMD ["obp-oidc-1.0.0-SNAPSHOT.jar"]
