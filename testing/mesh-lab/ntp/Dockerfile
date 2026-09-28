# NTP for lab devices without internet (an ESP32 over PPP): chrony serves
# the host's idea of the time, synced upstream when it can be, and its own
# clock (stratum 10) when not. -x: never touch the container's clock.
FROM alpine:3
RUN apk add --no-cache chrony
RUN printf 'pool pool.ntp.org iburst\nallow all\nlocal stratum 10\n' > /etc/chrony/chrony.conf
ENTRYPOINT ["chronyd", "-d", "-x", "-f", "/etc/chrony/chrony.conf"]
