FROM python:3.12-slim
# Устанавливаем рабочую директорию

WORKDIR /app/tentacula

# Копируем только зависимости (для кэширования)
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Открываем порт для Uvicorn
EXPOSE 5000

# Запускаем Uvicorn
CMD ["python", "app.py"]