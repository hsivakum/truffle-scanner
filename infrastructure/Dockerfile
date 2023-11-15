FROM alpine:3.16

# Copy the actual app executable (replace with the actual binary name)
COPY ./bin/truffle-scanner /usr/local/bin/truffle-scanner

RUN chmod +x /usr/local/bin/truffle-scanner

# Copy the Trufflehog executable to a directory in the PATH
COPY ./bin/trufflehog /usr/local/bin/

# Add the Trufflehog path to the PATH variable
ENV PATH="/usr/local/bin:${PATH}"

# Expose the CMD as the actual app executable
CMD ["truffle-scanner"]
