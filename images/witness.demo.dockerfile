FROM gleif/keri:latest

SHELL ["/bin/bash", "-c"]
EXPOSE 5632
EXPOSE 5633
EXPOSE 5634
EXPOSE 5642
EXPOSE 5643
EXPOSE 5644

RUN mkdir -p /usr/local/var/keri

ENTRYPOINT ["kli", "witness", "demo"]
