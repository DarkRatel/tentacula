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

# ---------- Копируем окружение и приложение ----------
COPY tentacula.tar.gz .
COPY ./app /app/tentacula/app
COPY config.cfg /app/tentacula/config.cfg
COPY certs /app/tentacula/certs
COPY schedulers /app/tentacula/schedulers
COPY suckers /app/tentacula/suckers

COPY composition_alias.json /app/tentacula/composition_alias.json

# ---------- Распаковка окружения ----------
RUN mkdir /opt/conda_env && \
    tar -xzf tentacula.tar.gz -C /opt/conda_env && \
    rm tentacula.tar.gz

# ---------- Настройка переменных окружения ----------
ENV PATH="/opt/conda_env/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ---------- Открываем порт ----------
EXPOSE 8000

# ---------- При запуске контейнера выполняем conda-unpack и стартуем сервер ----------
CMD ["/bin/bash", "-c", "/opt/conda_env/bin/conda-unpack && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
