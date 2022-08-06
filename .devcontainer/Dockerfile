ARG VARIANT="3.10-bullseye"
FROM python:${VARIANT}

RUN apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends sudo bash-completion vim sqlite3 \
    && adduser --disabled-password --gecos '' python \
    && adduser python sudo && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER python

COPY poetry.lock .
COPY pyproject.toml .
COPY .pre-commit-config.yaml .

ENV POETRY_VIRTUALENVS_CREATE="false"
ENV PATH="${PATH}:/home/python/.local/bin"
RUN pip install poetry \
    && poetry install
