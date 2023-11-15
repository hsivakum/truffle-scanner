FROM alpine:3.16

COPY ./bin/truffle-scanner /truffle-scanner
COPY ./bin/trufflehog /trufflehog

RUN chmod +x /truffle-scanner

# Create a user home directory
ENV HOME /home/scanner
RUN mkdir -p $HOME

# Add the directory to the PATH
ENV PATH="${HOME}:${PATH}"

CMD ["/truffle-scanner"]