FROM golang:1.10.2-alpine
RUN apk update
RUN apk upgrade
RUN apk add git
RUN mkdir /app
COPY . /app
WORKDIR /app
ENV GOPATH /app
RUN go get github.com/songgao/water # server is name of our application
RUN go get golang.org/x/net/ipv4
RUN CGO_ENABLED=1 GOOS=linux go build