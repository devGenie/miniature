FROM golang:1.10.2-alpine
RUN apk update
RUN apk upgrade
RUN apk add git
RUN apk add iptables
RUN mkdir /vpn
COPY . /vpn
WORKDIR /vpn
ENV GOPATH /vpn
RUN go get github.com/songgao/water
RUN go get github.com/robfig/cron
RUN go get golang.org/x/net/ipv4
RUN CGO_ENABLED=1 GOOS=linux go build