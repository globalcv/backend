FROM golang:1.14
COPY . /globalcv
WORKDIR /globalcv
RUN go get github.com/cespare/reflex
EXPOSE 8080
ENTRYPOINT ["reflex", "-c", "reflex.conf"]