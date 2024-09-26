FROM gradle:8.1.1-jdk17 AS build
WORKDIR /app
COPY --chown=gradle:gradle . /app
RUN gradle build --no-daemon

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/build/libs/*.jar ./burp-plugin.jar
ENTRYPOINT ["cp","/app/burp-plugin.jar","/tmp/burpsuite-project-file-parser-all.jar"]
