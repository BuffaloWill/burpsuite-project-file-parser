FROM gradle:6.9.4-jdk8 AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle fatJar

FROM openjdk:8-jre-slim
RUN mkdir /app
COPY --from=build /home/gradle/src/build/libs/*.jar /app/burp-plugin.jar
ENTRYPOINT ["cp","/app/burp-plugin.jar","/tmp/burpsuite-project-file-parser-all.jar"]
