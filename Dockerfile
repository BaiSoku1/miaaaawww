FROM python:3.11-slim

# Instalar Lua 5.3, utilidades necesarias y crear symlinks
RUN apt-get update && \
    apt-get install -y lua5.3 curl gcc && \
    ln -sf /usr/bin/lua5.3 /usr/bin/lua && \
    ln -sf /usr/bin/lua5.3 /usr/bin/lua5.3 && \
    rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el proyecto
COPY . .

# Exponer el puerto para Flask/web (si corresponde)
EXPOSE 8080

# Comando para iniciar el bot
CMD ["python", "cat.py"]
