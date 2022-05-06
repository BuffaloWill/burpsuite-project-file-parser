FROM gradle:4.7.0-jdk8-alpine AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle fatJar

FROM openjdk:8-jre-slim
RUN mkdir /app
COPY --from=build /home/gradle/src/build/libs/*.jar /app/burp-plugin.jar
ENTRYPOINT ["cp","/app/burp-plugin.jar","/tmp/burpsuite-project-file-parser-all.jar"]
