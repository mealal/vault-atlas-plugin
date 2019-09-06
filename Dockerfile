FROM golang:1.13
LABEL maintainer="Alexey Menshikov <mealal@github.com>"
WORKDIR /app
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN mkdir -p $GOPATH/src/github.com/mealal && cd $GOPATH/src/github.com/mealal && git clone https://github.com/mealal/vault-atlas-plugin && cd vault-atlas-plugin && ./build.sh && cp ./build/* /app/