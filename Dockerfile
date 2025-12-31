FROM gradle:8.11-jdk17 AS build
WORKDIR /app
COPY --chown=gradle:gradle . /app
RUN gradle build --no-daemon

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/build/libs/*.jar ./burp-plugin.jar
ENTRYPOINT ["cp","/app/burp-plugin.jar","/tmp/burpsuite-project-file-parser-all.jar"]
