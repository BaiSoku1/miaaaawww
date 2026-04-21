FROM python:3.11-slim

# Instala Lua 5.3, curl y gcc; crea symlink solo para 'lua'
RUN apt-get update && \
    apt-get install -y lua5.3 curl gcc && \
    ln -sf /usr/bin/lua5.3 /usr/bin/lua && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["python", "cat.py"]
