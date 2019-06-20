FROM golang:1.12.5-alpine
RUN apk update
RUN apk upgrade
RUN apk add git
RUN apk add iptables
RUN apk add bash
RUN mkdir /miniature
COPY . /miniature
WORKDIR /miniature
RUN export GO111MODULE=on
RUN go mod init github.com/devgenie/miniature
RUN CGO_ENABLED=1 GOOS=linux go build