FROM golang:1.21.5-alpine
RUN apk update
RUN apk upgrade
RUN apk add git
RUN apk add iptables
RUN apk add bash
RUN apk add curl
RUN apk add net-tools
RUN apk add tcpdump
RUN apk add tshark
RUN mkdir /miniature
COPY . /miniature
WORKDIR /miniature
RUN export GO111MODULE=on
