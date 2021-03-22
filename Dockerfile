FROM nikoskoutr/open-tee
RUN curl -sLO http://archive.ubuntu.com/ubuntu/pool/universe/p/polarssl/libpolarssl5_1.3.4-1_amd64.deb && apt install ./libpolarssl5_1.3.4-1_amd64.deb
RUN curl -sLO http://archive.ubuntu.com/ubuntu/pool/universe/p/polarssl/libpolarssl-dev_1.3.4-1_amd64.deb && apt install ./libpolarssl-dev_1.3.4-1_amd64.deb
COPY ./masker /masker

RUN cp -r /masker/CAs/* /Open-TEE/CAs
RUN cp -r /masker/TAs/* /Open-TEE/TAs
RUN rm -rf /masker
# RUN cd /Open-TEE && qbs debug