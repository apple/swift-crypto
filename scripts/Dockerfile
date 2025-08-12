# Defaults to 5.10
ARG SWIFT_VERSION_NUMBER=5.10
FROM swift:$SWIFT_VERSION_NUMBER-jammy
RUN apt-get update && apt-get install -y wget

# Download and extract the destination.json style SDK for armv7 for the chosen version and distro
ARG SWIFT_VERSION_NUMBER
ARG TARGET_DISTRO=ubuntu-jammy
ENV DOWNLOAD_FILE=swift-${SWIFT_VERSION_NUMBER}-RELEASE-${TARGET_DISTRO}-armv7-sdk.tar.gz
ENV DESTINATION_JSON=/opt/swift-${SWIFT_VERSION_NUMBER}-RELEASE-${TARGET_DISTRO}-armv7/${TARGET_DISTRO}.json
RUN wget -nc https://github.com/swift-embedded-linux/armhf-debian/releases/download/$SWIFT_VERSION_NUMBER/$DOWNLOAD_FILE && \
    tar -xf ${DOWNLOAD_FILE} -C /opt && \
    echo ${DESTINATION_JSON}
