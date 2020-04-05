FROM winlin/eosbuilder:v1.0.2 as builder
ARG branch=master
ARG symbol=SYS

RUN git clone -b $branch https://github.com/boscore/ibc_plugin_eos.git --recursive 

WORKDIR /ibc_plugin_eos
RUN ./scripts/eosio_build.sh -s EOS -y -P \
RUN ./scripts/eosio_install.sh

FROM ubuntu:18.04
USER root
RUN apt-get update \ 
    && DEBIAN_FRONTEND=noninteractive apt-get -y install openssl ca-certificates \ 
                                                        vim net-tools lsof wget curl supervisor \
                                                        libusb-1.0-0-dev curl libcurl4-gnutls-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/eosio/
COPY --from=builder /usr/local/lib/* /usr/local/lib/
COPY --from=builder /ibc_plugin_eos/build/bin /opt/eosio/bin

ENV EOSIO_ROOT=/opt/eosio
ENV LD_LIBRARY_PATH /usr/local/lib
ENV PATH /opt/eosio/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN wget -O /root/.bashrc https://raw.githubusercontent.com/EOSBIXIN/eostoolkit/master/bashrc
RUN mkdir /root/eosio-wallet
RUN wget -O /root/eosio-wallet/config.ini https://raw.githubusercontent.com/EOSBIXIN/eostoolkit/master/wallet_config.ini
RUN wget -O /opt/eosio/bin/nodeosd.sh https://raw.githubusercontent.com/EOSBIXIN/eostoolkit/master/others/bos/nodeosd.sh
RUN chmod a+x /opt/eosio/bin/nodeosd.sh
