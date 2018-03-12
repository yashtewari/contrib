FROM golang:1.8

RUN apt-get update && apt-get install -y \
    libpam0g-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pam /src/github.com/open-policy-agent/contrib/pam_authz/pam
COPY docker/run.dockerfile /run.dockerfile
COPY docker/keys/id_rsa.pub /id_rsa.pub
COPY docker/etc/pam.d /pam.d
COPY docker/etc/sshd_config /sshd_config
COPY docker/create_user.sh /create_user.sh

WORKDIR /src/github.com/open-policy-agent/contrib/pam_authz/pam

RUN make clean && make

# This creates a temporary context with files in /src/github.com/open-policy-agent/contrib/pam_authz/pam and / directories.
# The context is passed to other dockerfiles which use the files as needed.
CMD tar -cf - \
        -C /src/github.com/open-policy-agent/contrib/pam_authz/pam pam_authz.so \
        -C / run.dockerfile id_rsa.pub pam.d sshd_config create_user.sh
