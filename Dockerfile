FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH

# Keep the baseline image independent of the host Python installation while
# retaining the compilers needed by arbitrary Python targets' dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    git \
    libffi-dev \
    libssl-dev \
    pkg-config \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv "$VIRTUAL_ENV" \
    && python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install \
        pyre-check==0.9.23 \
        git+https://github.com/facebook/sapp.git@4c3d3086cbf447ec5cd53ea654751735c2c5f973 \
        requests==2.32.3 \
        openpyxl==3.1.5 \
        openai==1.35.13 \
        zhipuai==2.1.1.20240620.1 \
        tqdm==4.66.4 \
    && rm -rf /root/.cache/pip

WORKDIR /taintp2x
COPY . /taintp2x/

# Fail the image build if the baseline tools or the repository's direct
# Python imports are unavailable.
RUN python --version \
    && pyre --version client_and_binary \
    && sapp --help >/dev/null \
    && python -c "import openai, openpyxl, requests, zhipuai"

CMD ["bash"]
