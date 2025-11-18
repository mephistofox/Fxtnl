# fxTunnel

Простая и надёжная система dev-туннелей на Python. Полная альтернатива `ssh -L` с автоматическим переподключением, шифрованием, health checks и Docker поддержкой.

## Особенности

### Безопасность
- **AES-256-GCM шифрование** всего трафика
- **HMAC-SHA256 challenge-response** аутентификация
- **Host Key Verification** - защита от MITM атак (как в SSH)
- **Trust on first use** - первый клиент авторизуется автоматически
- **Контроль доступа к портам** на сервере

### Надёжность
- **Автоматическое переподключение** с exponential backoff и jitter
- **Heartbeat** каждые 15 секунд
- **Health check endpoint** для мониторинга
- **Graceful shutdown** с уведомлением клиентов

### Удобство
- **Нулевая конфигурация сервера** - просто запусти и работай
- **Профили подключений** в config.yaml
- **Множественные туннели** в одном соединении
- **Мульти-клиент** - несколько клиентов одновременно
- **Поддержка TCP и UDP**
- **Docker и Kubernetes** ready
- **Structured logging** (JSON для production)

---

## Установка

### Требования

- Python 3.13+
- Linux/macOS (Windows - экспериментально)

### Через uv (рекомендуется)

```bash
git clone https://github.com/user/fxtunnel ~/fxtunnel
cd ~/fxtunnel
uv sync
```

### Через pip

```bash
git clone https://github.com/user/fxtunnel ~/fxtunnel
cd ~/fxtunnel
pip install -e .
```

### Docker

```bash
docker build -t fxtunnel .
```

---

## Быстрый старт

### Сервер

```bash
# Базовый запуск
python main.py server

# Production с health check и JSON логами
python main.py server --health-port 8080 --log-json

# С ограничением портов
python main.py server --allowed-ports 5432,6379,80
```

### Клиент

```bash
# Один туннель
python main.py client --ip 192.168.1.100 -L 5432:5432

# Несколько туннелей
python main.py client --ip 192.168.1.100 -L 5432:5432 -L 6379:6379 -L 8080:80

# UDP туннель
python main.py client --ip 192.168.1.100 -L 53:53:udp

# Использование профиля
python main.py connect dev
```

---

## Формат туннеля

```
-L LOCAL_PORT:REMOTE_PORT[:MODE]
```

| Параметр | Описание |
|----------|----------|
| `LOCAL_PORT` | Локальный порт для прослушивания |
| `REMOTE_PORT` | Удалённый порт на сервере |
| `MODE` | `tcp` (по умолчанию) или `udp` |

### Примеры

```bash
# PostgreSQL
-L 5432:5432

# Разные порты (локальный 15432 -> удалённый 5432)
-L 15432:5432

# DNS через UDP
-L 53:53:udp

# Множественные
-L 5432:5432 -L 6379:6379 -L 8080:80
```

---

## Конфигурация

### Создание конфига

```bash
python main.py config init
```

Создаёт `~/.fxtunnel/config.yaml` (или `$FXTUNNEL_DATA_DIR/config.yaml`).

### Пример конфигурации

```yaml
# Настройки по умолчанию
defaults:
  bind: localhost
  verbose: false
  accept_new_host: false

# Профили подключений
profiles:
  dev:
    server: 192.168.1.100
    port: 9000
    tunnels:
      - local: 5432
        remote: 5432
      - local: 6379
        remote: 6379

  prod-db:
    server: db.example.com
    tunnels:
      - 5432:5432

  web:
    server: web.example.com
    tunnels:
      - local: 8080
        remote: 80
      - local: 5353
        remote: 53
        mode: udp

# Настройки сервера
server:
  port: 9000
  bind: 0.0.0.0
  max_clients: 10
  allowed_ports: [5432, 6379, 80, 443]
```

### Команды конфигурации

```bash
# Создать конфиг
python main.py config init

# Показать конфиг
python main.py config show

# Подключиться через профиль
python main.py connect dev

# С переопределением
python main.py connect dev --verbose --bind 0.0.0.0
```

---

## Команды

| Команда | Описание |
|---------|----------|
| `server` | Запустить сервер туннелей |
| `client` | Подключиться к серверу (ручная настройка) |
| `connect <profile>` | Подключиться используя профиль |
| `config init` | Создать файл конфигурации |
| `config show` | Показать текущую конфигурацию |
| `status` | Показать статус ключей и профилей |

---

## Параметры сервера

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `--port` | 9000 | Порт туннеля |
| `--bind` | 0.0.0.0 | Адрес привязки |
| `--max-clients` | 10 | Макс. одновременных клиентов |
| `--allowed-ports` | все | Разрешённые порты (через запятую) |
| `--health-port` | - | Порт для health check endpoint |
| `--log-json` | false | JSON формат логов |
| `--log-file` | - | Файл для записи логов |
| `-v, --verbose` | false | Подробный вывод |

### Health Check Endpoints

При указании `--health-port`:

| Endpoint | Описание |
|----------|----------|
| `/health` | Liveness check (uptime) |
| `/ready` | Readiness check |
| `/metrics` | Метрики (клиенты, трафик) |

```bash
# Запуск с health check
python main.py server --health-port 8080

# Проверка
curl http://localhost:8080/health
curl http://localhost:8080/metrics
```

---

## Параметры клиента

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `--ip` | обязательный | IP-адрес сервера |
| `--port` | 9000 | Порт туннеля на сервере |
| `-L` | обязательный | Спецификация туннеля |
| `--bind` | localhost | Локальный адрес привязки |
| `--accept-new-host` | false | Авто-принятие новых серверов |
| `--log-json` | false | JSON формат логов |
| `--log-file` | - | Файл для записи логов |
| `-v, --verbose` | false | Подробный вывод |

---

## Безопасность

### Host Key Verification

При первом подключении клиент сохраняет fingerprint сервера в `~/.fxtunnel/known_hosts`.

**Если fingerprint изменился:**
```
WARNING: SERVER IDENTITY HAS CHANGED!
This could indicate a man-in-the-middle attack!
```

**Действия:**
1. Убедитесь, что сервер был переустановлен
2. Удалите запись из `~/.fxtunnel/known_hosts`
3. Подключитесь снова

### Контроль доступа к портам

```bash
# CLI
python main.py server --allowed-ports 5432,6379,80

# config.yaml
server:
  allowed_ports: [5432, 6379, 80, 443]
```

### Рекомендации

1. Используйте файрвол для ограничения доступа к порту 9000
2. Ключи создаются с правами 600 автоматически
3. Регулярно ротируйте ключи
4. Ограничивайте `allowed_ports` на production серверах
5. Используйте `--log-json` для централизованного логирования

---

## Docker

### Быстрый старт

```bash
# Сборка
docker build -t fxtunnel .

# Запуск
docker run -d \
  --name fxtunnel-server \
  -p 9000:9000 \
  -p 8080:8080 \
  -v fxtunnel-data:/data \
  fxtunnel

# Логи
docker logs -f fxtunnel-server

# Health check
curl http://localhost:8080/health
```

### Docker Compose

```bash
docker-compose up -d
docker-compose logs -f
docker-compose down
```

### Production конфигурация

```bash
docker run -d \
  --name fxtunnel-server \
  --restart unless-stopped \
  -p 9000:9000 \
  -p 8080:8080 \
  -v fxtunnel-data:/data \
  --memory 256m \
  fxtunnel server \
  --health-port 8080 \
  --allowed-ports 5432,6379,80 \
  --max-clients 20 \
  --log-json
```

### Переменные окружения

| Переменная | Описание |
|------------|----------|
| `FXTUNNEL_DATA_DIR` | Директория для данных (default: `/data` в Docker) |

Подробнее: [docker/README.md](docker/README.md)

---

## Systemd

### Установка сервиса

```bash
mkdir -p ~/.config/systemd/user
cp ~/fxtunnel/systemd/fxtunnel.service ~/.config/systemd/user/

systemctl --user daemon-reload
systemctl --user enable fxtunnel
systemctl --user start fxtunnel

# Для запуска без логина
sudo loginctl enable-linger $USER

# Логи
journalctl --user -u fxtunnel -f
```

### Firewall

```bash
# UFW
sudo ufw allow 9000/tcp

# firewalld
sudo firewall-cmd --add-port=9000/tcp --permanent
sudo firewall-cmd --reload
```

---

## Архитектура

```
[Приложение] → [localhost:local_port] → [Клиент]
                                           ↓
                                    [Туннель (AES-256-GCM)]
                                           ↓
                                       [Сервер] → [localhost:remote_port] → [Сервис]
```

### Протокол

- **Framed messages**: `[4 bytes length][encrypted payload]`
- **Шифрование**: AES-256-GCM
- **Аутентификация**: HMAC-SHA256 challenge-response
- **Heartbeat**: PING/PONG каждые 15 сек
- **Таймаут**: 60 сек

### Автоматическое переподключение

Exponential backoff с jitter:
- 1 сек → 2 сек → 4 сек → ... → max 30 сек
- 10% jitter для избежания thundering herd

---

## Файлы данных

| Путь | Описание |
|------|----------|
| `~/.fxtunnel/key` | Ключ авторизации клиента |
| `~/.fxtunnel/known_hosts` | Известные серверы |
| `~/.fxtunnel/config.yaml` | Конфигурация |
| `~/.fxtunnel/server_key` | Ключ идентификации сервера |
| `~/.fxtunnel/authorized_key` | Авторизованный ключ на сервере |

Путь можно изменить через `FXTUNNEL_DATA_DIR`.

---

## Устранение неполадок

### Клиент не подключается

```bash
# Проверить доступность
nc -zv <server_ip> 9000

# Проверить firewall
sudo ss -tlnp | grep 9000

# Проверить статус сервиса
systemctl --user status fxtunnel
```

### Authentication failed

```bash
# Сбросить ключ на сервере
rm ~/.fxtunnel/authorized_key
systemctl --user restart fxtunnel
```

### SERVER IDENTITY HAS CHANGED

```bash
# Удалить старую запись
nano ~/.fxtunnel/known_hosts
# Удалите строку с адресом сервера
```

### Порт занят

```bash
sudo lsof -i :5432
sudo ss -tlnp | grep 5432
```

### Port not allowed

Сервер отклоняет подключение. Добавьте порт в `--allowed-ports` или `config.yaml`.

---

## Сравнение с SSH -L

| Функция | SSH -L | fxTunnel |
|---------|--------|----------|
| Автопереподключение | Нет | Да |
| Heartbeat | Нет | Да |
| Множественные туннели | По одному | Да |
| Host key verification | Да | Да |
| Конфигурация сервера | Нужна | Не нужна |
| Профили | ~/.ssh/config | config.yaml |
| UDP | Нет | Да |
| Шифрование | SSH | AES-256-GCM |
| Мульти-клиент | Да | Да |
| Health checks | Нет | Да |
| Docker | - | Да |
| Structured logging | - | Да |

---

## Разработка

### Установка dev зависимостей

```bash
uv sync --all-extras
```

### Запуск тестов

```bash
uv run pytest tests/ -v
```

### Линтинг

```bash
uv run ruff check .
uv run mypy fxtunnel
```

---

## Структура проекта

```
fxTunnel/
├── .github/
│   └── workflows/
│       └── ci.yml
├── docker/
│   └── README.md
├── fxtunnel/
│   ├── __init__.py
│   ├── protocol.py
│   ├── server.py
│   ├── client.py
│   ├── config.py
│   ├── logging.py
│   └── health.py
├── systemd/
│   └── fxtunnel.service
├── tests/
│   ├── test_protocol.py
│   ├── test_config.py
│   └── test_integration.py
├── main.py
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Зависимости

```toml
dependencies = [
    "cryptography>=42.0.0",
    "pyyaml>=6.0",
    "structlog>=24.0.0",
    "aiohttp>=3.9.0",
]
```

---

## Лицензия

MIT
