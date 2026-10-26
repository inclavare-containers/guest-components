# SPDX-License-Identifier: Apache-2.0
ARG BASE_IMAGE=registry.openanolis.cn/openanolis/anolisos:23.4
FROM ${BASE_IMAGE}

# Cloud Linux images default to a VPC-only mirror; native CI also runs outside ECS.
RUN sed -i -E 's|https?://mirrors.cloud.aliyuncs.com/|https://mirrors.aliyun.com/|g' /etc/yum.repos.d/*.repo
RUN printf '\nmax_parallel_downloads=20\n' >> /etc/dnf/dnf.conf
RUN dnf install -y ca-certificates curl tar gzip xz rpm-build clang perl protobuf-devel git libgudev-devel openssl-devel tpm2-tss-devel gcc gcc-c++ make rsync file binutils
RUN if [ "$(uname -m)" = x86_64 ]; then \
      if grep -q '^ID=\"\?anolis' /etc/os-release; then dnf install -y anolis-epao-release; fi; \
      dnf install -y libtdx-attest-devel; \
    fi

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo
ENV PATH=/opt/cargo/bin:$PATH
ARG RUST_VERSION=1.88.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh && \
    sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain "${RUST_VERSION}" --no-modify-path && \
    rm /tmp/rustup-init.sh
ENV CARGO_BUILD_JOBS=2 OPENSSL_NO_VENDOR=1
COPY build-in-container.sh /usr/local/bin/build-rpm
ENTRYPOINT ["bash", "/usr/local/bin/build-rpm"]
