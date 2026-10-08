FROM ubuntu:18.04

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y git build-essential wget zlib1g-dev golang-go python-pip python-dev build-essential cmake && \
    apt-get clean


ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    GOPATH=/go \
    PATH=/clang+llvm/bin:/usr/local/cargo/bin:/reusing-scanner/bin/:/go/bin:$PATH \
    LD_LIBRARY_PATH=/clang+llvm/lib:$LD_LIBRARY_PATH

RUN mkdir -p reusing-scanner
COPY . reusing-scanner
WORKDIR reusing-scanner

RUN ./build/install_rust.sh
RUN PREFIX=/ ./build/install_llvm.sh
RUN ./build/install_tools.sh
RUN ./build/build.sh

# VOLUME ["/data"]
WORKDIR /data
# ENTRYPOINT [ "/opt/env.init" ]
