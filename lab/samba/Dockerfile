# activeDIQ AD lab — Samba 4 AD DC image. TEST INFRASTRUCTURE ONLY: Samba is GPL-3.0 and is
# never shipped, bundled or linked into the product (licence register, T-0012).
# Base pinned by multi-arch index digest (debian:trixie-slim); works on linux/arm64 and linux/amd64.
FROM debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision samba-dsdb-modules python3-samba winbind krb5-user ldb-tools ldap-utils \
      faketime openssl acl attr tar procps ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf

COPY samba/entrypoint.sh /usr/local/bin/lab-entrypoint
COPY seed/generate.py /opt/lab/seed/generate.py
COPY seed/post-start.sh /opt/lab/seed/post-start.sh
RUN chmod 0755 /usr/local/bin/lab-entrypoint /opt/lab/seed/post-start.sh

EXPOSE 389 636 3268 3269 88/tcp 88/udp 464/tcp 464/udp
HEALTHCHECK --interval=5s --timeout=5s --start-period=20s --retries=60 \
  CMD ["/usr/local/bin/lab-entrypoint", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
CMD ["serve"]
