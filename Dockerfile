FROM golang:1.18-alpine

ARG GITHUB_ACCOUNT_NAME
ARG APP_NAME

ENV ROOT=/go/src/${GITHUB_ACCOUNT_NAME}/${APP_NAME}

WORKDIR ${ROOT}
COPY . .

RUN apk add --no-cache alpine-sdk git && \
    go install github.com/cosmtrek/air@latest
