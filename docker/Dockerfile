FROM eclipse-temurin:21-jdk-alpine AS base

RUN apk add --no-cache bash

VOLUME /tmp

WORKDIR /var/application

FROM base AS builder

VOLUME /tmp

WORKDIR /var/application

COPY ./ ./

RUN bash deploy.sh

FROM base AS runner

WORKDIR /var/application

COPY --from=builder /var/application/target/*.jar app.jar

ENTRYPOINT java -jar -Dspring.profiles.active=${PROFILE} app.jar
