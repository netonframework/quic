# The neton quic endpoint for the QUIC Interop Runner. Build the binary first:
#   ./gradlew -p interop/runner linkReleaseExecutableLinuxX64
#   docker build -t neton-quic-interop interop/runner
FROM martenseemann/quic-network-simulator-endpoint:latest

COPY build/bin/linuxX64/releaseExecutable/endpoint.kexe /neton-quic-endpoint
COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /neton-quic-endpoint /run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
