FROM python:3.11-slim

# Instala Lua 5.3 y utilidades requeridas
RUN apt-get update && \
    apt-get install -y lua5.3 curl gcc && \
    rm -rf /var/lib/apt/lists/*

# Instala dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo tu proyecto
COPY . .

# Expone el puerto para Flask (o el que uses)
EXPOSE 8080

# Ejecuta tu bot (ajusta si tu archivo es diferente)
CMD ["python", "cat.py"]
