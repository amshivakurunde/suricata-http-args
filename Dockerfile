FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Suricata build dependencies
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cargo \
    cbindgen \
    ca-certificates \
    libjansson-dev \
    libpcap-dev \
    libpcre2-dev \
    libtool \
    libyaml-dev \
    libcap-ng-dev \
    libmagic-dev \
    libnet1-dev \
    make \
    pkg-config \
    rustc \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/suricata

# Copy our modified Suricata source
COPY . .

# Build our Suricata version
RUN ./autogen.sh && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --disable-gccmarch-native && \
    make -j2 && \
    make install && \
    make install-conf

# Directories used when testing PCAPs and custom rules
RUN mkdir -p \
    /data \
    /rules \
    /var/log/suricata \
    /var/lib/suricata/rules && \
    touch /var/lib/suricata/rules/suricata.rules

ENTRYPOINT ["/usr/bin/suricata"]

CMD ["--build-info"]
