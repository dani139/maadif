# =============================================================================
# MAADIF - Mobile & Application Analysis Docker Image Framework
# =============================================================================
# Multi-stage build for optimal caching and organization
# =============================================================================

# -----------------------------------------------------------------------------
# Stage: base - Common dependencies and system packages
# -----------------------------------------------------------------------------
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Java (full JDK for compilation)
    openjdk-21-jdk \
    # Python
    python3 python3-pip python3-venv python3-dev \
    # Core utilities
    git curl wget unzip zip p7zip-full zstd ca-certificates \
    # Binary analysis
    binutils binwalk file xxd patchelf \
    # Data tools
    sqlite3 jq \
    # Android tools
    android-tools-adb android-tools-fastboot \
    # Build tools
    build-essential cmake ninja-build pkg-config maven aapt \
    # Libraries
    libssl-dev libffi-dev zlib1g-dev \
    # Terminal tools
    tmux neovim \
    # Network tools
    nmap tcpdump tshark httpie \
    # GUI dependencies (for tools that need it)
    fontconfig libxrender1 libxtst6 libxi6 libxext6 libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# -----------------------------------------------------------------------------
# Stage: ghidra-downloader - Download and extract Ghidra
# -----------------------------------------------------------------------------
FROM base AS ghidra-downloader

ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_DATE=20260303

RUN curl -fsSL -o /tmp/ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    chmod +x /opt/ghidra/ghidraRun /opt/ghidra/support/analyzeHeadless

# -----------------------------------------------------------------------------
# Stage: jadx-downloader - Download and extract JADX
# -----------------------------------------------------------------------------
FROM base AS jadx-downloader

ARG JADX_VERSION=1.5.1

RUN curl -fsSL -o /tmp/jadx.zip \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    rm /tmp/jadx.zip && \
    chmod +x /opt/jadx/bin/*

# -----------------------------------------------------------------------------
# Stage: apktool-downloader - Download apktool
# -----------------------------------------------------------------------------
FROM base AS apktool-downloader

ARG APKTOOL_VERSION=2.10.0

RUN curl -fsSL -o /opt/apktool.jar \
    "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar"

# -----------------------------------------------------------------------------
# Stage: dex2jar-downloader - Download dex2jar
# -----------------------------------------------------------------------------
FROM base AS dex2jar-downloader

ARG DEX2JAR_VERSION=2.4

RUN curl -fsSL -o /tmp/dex2jar.zip \
    "https://github.com/pxb1988/dex2jar/releases/download/v${DEX2JAR_VERSION}/dex-tools-v${DEX2JAR_VERSION}.zip" && \
    unzip -q /tmp/dex2jar.zip -d /opt && \
    mv /opt/dex-tools-v${DEX2JAR_VERSION} /opt/dex2jar && \
    rm /tmp/dex2jar.zip && \
    chmod +x /opt/dex2jar/*.sh

# -----------------------------------------------------------------------------
# Stage: smali-downloader - Download smali/baksmali (pre-built executables)
# -----------------------------------------------------------------------------
FROM base AS smali-downloader

ARG SMALI_VERSION=2.5.2

RUN mkdir -p /opt/smali && \
    # Download the fat jars with all dependencies from bitbucket
    curl -fsSL -o /opt/smali/smali.jar \
    "https://bitbucket.org/JesusFreke/smali/downloads/smali-${SMALI_VERSION}.jar" && \
    curl -fsSL -o /opt/smali/baksmali.jar \
    "https://bitbucket.org/JesusFreke/smali/downloads/baksmali-${SMALI_VERSION}.jar"

# -----------------------------------------------------------------------------
# Stage: radare2-builder - Build radare2 from source
# -----------------------------------------------------------------------------
FROM base AS radare2-builder

RUN git clone --depth=1 https://github.com/radareorg/radare2.git /tmp/r2 && \
    cd /tmp/r2 && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install DESTDIR=/opt/radare2-install

# -----------------------------------------------------------------------------
# Stage: cutter-downloader - Download Cutter AppImage
# -----------------------------------------------------------------------------
FROM base AS cutter-downloader

ARG CUTTER_VERSION=2.4.1

RUN curl -fsSL -o /opt/Cutter.AppImage \
    "https://github.com/rizinorg/cutter/releases/download/v${CUTTER_VERSION}/Cutter-v${CUTTER_VERSION}-Linux-x86_64.AppImage" && \
    chmod +x /opt/Cutter.AppImage

# -----------------------------------------------------------------------------
# Stage: final - Combine everything
# -----------------------------------------------------------------------------
FROM base AS final

LABEL maintainer="maadif"
LABEL description="Mobile & Application Analysis Docker Image Framework"
LABEL version="1.0.0"

# Copy Ghidra
COPY --from=ghidra-downloader /opt/ghidra /opt/ghidra

# Copy JADX
COPY --from=jadx-downloader /opt/jadx /opt/jadx

# Copy apktool
COPY --from=apktool-downloader /opt/apktool.jar /opt/apktool/apktool.jar

# Copy dex2jar
COPY --from=dex2jar-downloader /opt/dex2jar /opt/dex2jar

# Copy smali/baksmali
COPY --from=smali-downloader /opt/smali /opt/smali

# Copy radare2
COPY --from=radare2-builder /opt/radare2-install/usr/local /usr/local

# Copy Cutter
COPY --from=cutter-downloader /opt/Cutter.AppImage /opt/cutter/Cutter.AppImage

# Create wrapper scripts
RUN mkdir -p /usr/local/bin && \
    # apktool wrapper
    printf '#!/bin/sh\nexec java -jar /opt/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool && \
    # smali wrapper
    printf '#!/bin/sh\nexec java -jar /opt/smali/smali.jar "$@"\n' > /usr/local/bin/smali && \
    chmod +x /usr/local/bin/smali && \
    # baksmali wrapper
    printf '#!/bin/sh\nexec java -jar /opt/smali/baksmali.jar "$@"\n' > /usr/local/bin/baksmali && \
    chmod +x /usr/local/bin/baksmali && \
    # cutter wrapper
    printf '#!/bin/sh\nexec /opt/cutter/Cutter.AppImage --appimage-extract-and-run "$@"\n' > /usr/local/bin/cutter && \
    chmod +x /usr/local/bin/cutter

# Create symlinks
RUN ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui && \
    ln -s /opt/dex2jar/d2j-dex2jar.sh /usr/local/bin/d2j-dex2jar

# Download SQLite JDBC driver
RUN curl -fsSL -o /opt/sqlite-jdbc.jar \
    "https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.45.1.0/sqlite-jdbc-3.45.1.0.jar"

# Install Python packages
RUN pip install --break-system-packages --no-cache-dir \
    androguard \
    frida-tools \
    objection \
    capstone \
    unicorn \
    keystone-engine \
    lief \
    pyelftools \
    angr \
    pwntools \
    ropper \
    r2pipe \
    mitmproxy \
    rich \
    requests \
    httpx \
    pyghidra \
    ghidriff \
    cloudscraper \
    beautifulsoup4

# Update library cache for radare2
RUN ldconfig

# Environment variables
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="/opt/ghidra:/opt/ghidra/support:/opt/jadx/bin:/opt/dex2jar:${PATH}"

# Create workspace
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
