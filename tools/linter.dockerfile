FROM golang:1.15

RUN go get -u golang.org/x/lint/golint

ENTRYPOINT ["golint"]
