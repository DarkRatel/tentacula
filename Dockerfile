FROM ubuntu:22.04

# ---------- Установка зависимостей ----------
RUN apt-get update && apt-get install -y \
    bash \
    bzip2 \
    tar \
    ca-certificates \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/tentacula

# ---------- Копирование окружения и приложения ----------
COPY tentacula.tar.gz /app/tentacula/tentacula.tar.gz
COPY ./app /app/tentacula/app
COPY config.cfg /app/tentacula/config.cfg
COPY composition_alias.json /app/tentacula/composition_alias.json
COPY certs /app/tentacula/certs
COPY schedulers /app/tentacula/schedulers
COPY suckers /app/tentacula/suckers

# ---------- Распаковка окружения ----------
RUN mkdir /app/tentacula/conda_env && \
    tar -xzf tentacula.tar.gz -C /app/tentacula/conda_env && \
    rm tentacula.tar.gz

# ---------- Настройка переменных окружения ----------
ENV PATH="/app/tentacula/conda_env/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ---------- Открытие порта ----------
EXPOSE 8000

# ---------- Запуск контейнера Conda и старт сервера ----------
CMD ["/bin/bash", "-c", "/app/tentacula/conda_env/bin/conda-unpack && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
