# Pinned WiX 5.0.2 (MS-RL, no OSMF fee; licence register "WiX Toolset") run under Wine, because WiX needs a
# real msi.dll and the factory host is Linux without a Windows VM (T-0702). Never bump WiX past 5.x
# without a money decision: 6.x/7.x carry the Open Source Maintenance Fee.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
ARG DOTNET_VERSION=8.0.33
ARG DOTNET_SHA256=d88b9624950fd33ffd561462f4a23d7ef6d4173ddef55d198adab07016bc5b8c
ARG WIX_VERSION=5.0.2
ARG WIX_SHA256=f30ef0c74e2a986126539c5780be93ac24e8136eaf723b1937b26272703ae173
RUN apt-get update && apt-get install -y --no-install-recommends wine wine64 xvfb xauth ca-certificates curl python3 \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; mkdir -p /opt/dotnet /opt/wix; cd /tmp; \
 curl -fsSL -o dn.zip "https://builds.dotnet.microsoft.com/dotnet/Runtime/${DOTNET_VERSION}/dotnet-runtime-${DOTNET_VERSION}-win-x64.zip"; \
 echo "${DOTNET_SHA256}  dn.zip" | sha256sum -c -; \
 curl -fsSL -o wix.nupkg "https://api.nuget.org/v3-flatcontainer/wix/${WIX_VERSION}/wix.${WIX_VERSION}.nupkg"; \
 echo "${WIX_SHA256}  wix.nupkg" | sha256sum -c -; \
 python3 -I -c "import zipfile;zipfile.ZipFile('dn.zip').extractall('/opt/dotnet');z=zipfile.ZipFile('wix.nupkg');[z.extract(n,'/opt/wix') for n in z.namelist() if n.startswith('tools/net6.0/any/')]"; \
 rm dn.zip wix.nupkg
ENV WINEDEBUG=-all WINEPREFIX=/tmp/pfx DOTNET_ROLL_FORWARD=Major
