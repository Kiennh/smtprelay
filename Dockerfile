FROM golang:1.19-alpine AS builder

COPY . /opt/

RUN cd /opt/ && go get ./... && go build -o mail .


FROM alpine:latest
MAINTAINER toan.nguyen@evgcorp.net

COPY --from=builder /opt/mail /usr/local/bin/mail

ENTRYPOINT ["/usr/local/bin/mail", "-config", "/opt/smtprelay.ini"]

EXPOSE 53 5300 9001 8500
