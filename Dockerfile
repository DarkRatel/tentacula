FROM python:3.12-slim
# Устанавливаем рабочую директорию

WORKDIR /app/tentacula

# Копируем только зависимости (для кэширования)
COPY requirements.txt .

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Открываем порт для Uvicorn
EXPOSE 8000

# Запускаем Uvicorn
CMD ["python", "app.py"]