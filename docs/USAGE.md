# fxTunnel - Полное руководство пользователя

Подробная документация по всем возможностям fxTunnel v0.4.0.

---

## Содержание

1. [Введение](#введение)
2. [Установка](#установка)
3. [Быстрый старт](#быстрый-старт)
4. [Режим сервера](#режим-сервера)
5. [Режим клиента](#режим-клиента)
6. [Профили подключений](#профили-подключений)
7. [Безопасность](#безопасность)
8. [Мониторинг и Health Checks](#мониторинг-и-health-checks)
9. [Логирование](#логирование)
10. [Docker](#docker)
11. [Systemd](#systemd)
12. [Продвинутое использование](#продвинутое-использование)
13. [Устранение неполадок](#устранение-неполадок)
14. [Протокол и архитектура](#протокол-и-архитектура)

---

## Введение

fxTunnel - это система туннелирования портов, разработанная как альтернатива `ssh -L` с дополнительными возможностями:

- Автоматическое переподключение при разрыве связи
- Множественные туннели в одном соединении
- Поддержка TCP и UDP
- Профили для быстрого подключения
- Health check endpoint для мониторинга
- Структурированное логирование
- Docker и Kubernetes поддержка

### Принцип работы

```
[Ваше приложение] → [localhost:local_port] → [fxTunnel клиент]
                                                    ↓
                                          [Зашифрованный туннель]
                                                    ↓
                                            [fxTunnel сервер] → [localhost:remote_port] → [Целевой сервис]
```

---

## Установка

### Системные требования

- **Python**: 3.13 или выше
- **ОС**: Linux, macOS (Windows - экспериментально)
- **Порты**: 9000 (туннель), 8080 (health check)

### Установка через uv (рекомендуется)

```bash
# Клонирование репозитория
git clone https://github.com/user/fxtunnel ~/fxtunnel
cd ~/fxtunnel

# Установка зависимостей
uv sync

# Проверка установки
uv run python main.py --version
```

### Установка через pip

```bash
git clone https://github.com/user/fxtunnel ~/fxtunnel
cd ~/fxtunnel

# Установка в режиме разработки
pip install -e .

# Проверка
python main.py --version
```

### Установка dev-зависимостей

Для разработки и тестирования:

```bash
uv sync --all-extras
```

Это установит pytest, ruff, mypy и другие инструменты.

---

## Быстрый старт

### Минимальный пример

**На сервере (удалённая машина):**
```bash
python main.py server
```

**На клиенте (локальная машина):**
```bash
python main.py client --ip <server_ip> -L 5432:5432
```

Теперь подключение к `localhost:5432` будет перенаправлено на `server:5432`.

### Несколько туннелей

```bash
python main.py client --ip 192.168.1.100 \
  -L 5432:5432 \
  -L 6379:6379 \
  -L 8080:80
```

---

## Режим сервера

### Базовый запуск

```bash
python main.py server
```

Сервер запустится на `0.0.0.0:9000` с настройками по умолчанию.

### Все параметры сервера

| Параметр | Значение | Описание |
|----------|----------|----------|
| `--port` | 9000 | Порт для туннельных подключений |
| `--bind` | 0.0.0.0 | IP-адрес для привязки |
| `--max-clients` | 10 | Максимум одновременных клиентов |
| `--allowed-ports` | все | Список разрешённых портов через запятую |
| `--health-port` | - | Порт для HTTP health check |
| `--log-json` | false | Вывод логов в JSON формате |
| `--log-file` | - | Путь к файлу логов |
| `-v, --verbose` | false | Подробный вывод (debug level) |

### Примеры запуска сервера

**Базовый сервер:**
```bash
python main.py server
```

**С кастомным портом:**
```bash
python main.py server --port 8000
```

**С ограничением портов:**
```bash
python main.py server --allowed-ports 5432,6379,80,443
```

**Production конфигурация:**
```bash
python main.py server \
  --port 9000 \
  --max-clients 50 \
  --allowed-ports 5432,6379,80,443 \
  --health-port 8080 \
  --log-json \
  --log-file /var/log/fxtunnel.log
```

**Только для локальных подключений:**
```bash
python main.py server --bind 127.0.0.1
```

### Поведение сервера

1. **Первый запуск**: генерируется `~/.fxtunnel/server_key`
2. **Первое подключение клиента**: сохраняется `~/.fxtunnel/authorized_key` (TOFU)
3. **Последующие подключения**: challenge-response аутентификация
4. **При разрыве**: клиент автоматически переподключается

### Файлы сервера

| Файл | Описание |
|------|----------|
| `~/.fxtunnel/server_key` | Ключ идентификации сервера |
| `~/.fxtunnel/authorized_key` | Авторизованный ключ клиента |

---

## Режим клиента

### Базовый синтаксис

```bash
python main.py client --ip <server_ip> -L <local>:<remote>[:<mode>]
```

### Все параметры клиента

| Параметр | Значение | Описание |
|----------|----------|----------|
| `--ip` | обязательный | IP-адрес или hostname сервера |
| `--port` | 9000 | Порт сервера |
| `-L` | обязательный | Спецификация туннеля (можно несколько) |
| `--bind` | localhost | Локальный адрес для прослушивания |
| `--accept-new-host` | false | Автоматически принимать новые серверы |
| `--log-json` | false | Вывод логов в JSON |
| `--log-file` | - | Путь к файлу логов |
| `-v, --verbose` | false | Подробный вывод |

### Формат туннеля (-L)

```
-L LOCAL_PORT:REMOTE_PORT[:MODE]
```

- `LOCAL_PORT` - порт на локальной машине
- `REMOTE_PORT` - порт на сервере
- `MODE` - `tcp` (по умолчанию) или `udp`

### Примеры клиентских подключений

**Один TCP туннель:**
```bash
python main.py client --ip 192.168.1.100 -L 5432:5432
```

**Несколько туннелей:**
```bash
python main.py client --ip 192.168.1.100 \
  -L 5432:5432 \
  -L 6379:6379 \
  -L 8080:80
```

**UDP туннель (например, DNS):**
```bash
python main.py client --ip 192.168.1.100 -L 5353:53:udp
```

**Разные локальные и удалённые порты:**
```bash
python main.py client --ip 192.168.1.100 -L 15432:5432
```

**Доступ с других машин в сети:**
```bash
python main.py client --ip 192.168.1.100 -L 5432:5432 --bind 0.0.0.0
```

**Автоматическое принятие нового сервера:**
```bash
python main.py client --ip 192.168.1.100 -L 5432:5432 --accept-new-host
```

**С логированием в файл:**
```bash
python main.py client --ip 192.168.1.100 -L 5432:5432 \
  --log-file ~/fxtunnel-client.log \
  --verbose
```

### Файлы клиента

| Файл | Описание |
|------|----------|
| `~/.fxtunnel/key` | Ключ авторизации клиента |
| `~/.fxtunnel/known_hosts` | Fingerprints известных серверов |
| `~/.fxtunnel/config.yaml` | Конфигурация и профили |

### Автоматическое переподключение

При потере соединения клиент автоматически переподключается:

- Начальная задержка: 1 секунда
- Максимальная задержка: 30 секунд
- Алгоритм: exponential backoff с 10% jitter

---

## Профили подключений

Профили позволяют сохранить настройки подключения и использовать их повторно.

### Создание конфигурации

```bash
python main.py config init
```

Создаёт файл `~/.fxtunnel/config.yaml`.

### Структура конфигурации

```yaml
# Настройки по умолчанию (наследуются всеми профилями)
defaults:
  bind: localhost
  verbose: false
  accept_new_host: false

# Профили подключений
profiles:
  # Профиль для разработки
  dev:
    server: 192.168.1.100
    port: 9000
    tunnels:
      - local: 5432
        remote: 5432
      - local: 6379
        remote: 6379

  # Профиль для production базы данных
  prod-db:
    server: db.example.com
    port: 9000
    verbose: true
    tunnels:
      - 5432:5432

  # Профиль с UDP
  dns-server:
    server: dns.example.com
    tunnels:
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

### Форматы туннелей в конфиге

**Полный формат (dict):**
```yaml
tunnels:
  - local: 5432
    remote: 5432
    mode: tcp
```

**Краткий формат (string):**
```yaml
tunnels:
  - 5432:5432
  - 6379:6379
  - 53:53:udp
```

### Использование профилей

**Подключение через профиль:**
```bash
python main.py connect dev
```

**С переопределением настроек:**
```bash
python main.py connect dev --verbose --bind 0.0.0.0
```

**С авто-принятием нового сервера:**
```bash
python main.py connect prod-db --accept-new-host
```

### Команды конфигурации

**Создать конфиг:**
```bash
python main.py config init
```

**Принудительно перезаписать:**
```bash
python main.py config init --force
```

**Показать текущий конфиг:**
```bash
python main.py config show
```

### Просмотр статуса

```bash
python main.py status
```

Показывает:
- Путь к конфигу и доступные профили
- Fingerprint клиентского ключа
- Известные хосты
- Fingerprint серверного ключа (если есть)

---

## Безопасность

### Шифрование

Весь трафик шифруется с использованием **AES-256-GCM**:
- 256-битный ключ
- 12-байтный случайный nonce для каждого сообщения
- Аутентификация данных (AEAD)

### Аутентификация

**Challenge-response (HMAC-SHA256):**
1. Сервер отправляет случайный 32-байтный challenge
2. Клиент вычисляет HMAC-SHA256(key, challenge)
3. Сервер проверяет ответ

**Trust on First Use (TOFU):**
- Первый подключившийся клиент автоматически авторизуется
- Его ключ сохраняется на сервере
- Последующие клиенты должны иметь этот же ключ

### Host Key Verification

Защита от MITM-атак (как в SSH):

1. Сервер генерирует identity key при первом запуске
2. Клиент сохраняет fingerprint в `~/.fxtunnel/known_hosts`
3. При несовпадении - предупреждение

**Если fingerprint изменился:**
```
WARNING: SERVER IDENTITY HAS CHANGED!
This could indicate a man-in-the-middle attack!
```

**Решение:**
```bash
# Удалить старую запись
nano ~/.fxtunnel/known_hosts
# Удалите строку с IP:PORT сервера
```

### Контроль доступа к портам

Ограничение портов, к которым клиенты могут подключаться:

**Через CLI:**
```bash
python main.py server --allowed-ports 5432,6379,80,443
```

**Через config.yaml:**
```yaml
server:
  allowed_ports: [5432, 6379, 80, 443]
```

При попытке подключения к неразрешённому порту клиент получит ошибку.

### Безопасность файлов

Ключи автоматически создаются с правами 600 (только владелец).

**Проверка:**
```bash
ls -la ~/.fxtunnel/
```

**Ручная установка прав:**
```bash
chmod 600 ~/.fxtunnel/key
chmod 600 ~/.fxtunnel/server_key
chmod 600 ~/.fxtunnel/authorized_key
```

### Рекомендации по безопасности

1. **Firewall**: ограничьте доступ к порту 9000
2. **allowed_ports**: используйте whitelist портов
3. **Ротация ключей**: периодически пересоздавайте ключи
4. **Мониторинг**: используйте health check и логи
5. **TLS**: рассмотрите VPN для дополнительной защиты канала

---

## Мониторинг и Health Checks

### Включение health check

```bash
python main.py server --health-port 8080
```

### Доступные endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/health` | GET | Liveness check |
| `/ready` | GET | Readiness check |
| `/metrics` | GET | Метрики сервера |

### Примеры запросов

**Liveness check:**
```bash
curl http://localhost:8080/health
```

Ответ:
```json
{
  "status": "healthy",
  "uptime_seconds": 3600
}
```

**Readiness check:**
```bash
curl http://localhost:8080/ready
```

Ответ:
```json
{
  "status": "ready",
  "details": {
    "server": "running"
  }
}
```

**Метрики:**
```bash
curl http://localhost:8080/metrics
```

Ответ:
```json
{
  "uptime_seconds": 3600,
  "clients_connected": 3,
  "bytes_sent": 1048576,
  "bytes_received": 2097152,
  "connections_total": 42
}
```

### Использование с Kubernetes

**Liveness probe:**
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
```

**Readiness probe:**
```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Мониторинг с Prometheus

Метрики можно скрейпить с `/metrics` endpoint.

---

## Логирование

### Режимы логирования

fxTunnel поддерживает структурированное логирование через structlog.

### Параметры логирования

| Параметр | Описание |
|----------|----------|
| `-v, --verbose` | Debug level вместо Info |
| `--log-json` | JSON формат для production |
| `--log-file` | Запись в файл |

### Примеры

**Консольный вывод (по умолчанию):**
```bash
python main.py server -v
```

Вывод:
```
2024-01-15 10:30:45 [info     ] Tunnel server listening        bind=0.0.0.0 port=9000
2024-01-15 10:30:50 [info     ] Client connected               client=192.168.1.50:45678
```

**JSON формат:**
```bash
python main.py server --log-json
```

Вывод:
```json
{"event": "Tunnel server listening", "bind": "0.0.0.0", "port": 9000, "level": "info", "timestamp": "2024-01-15T10:30:45Z"}
```

**Запись в файл:**
```bash
python main.py server --log-file /var/log/fxtunnel.log --log-json
```

### Контекстная информация

Логи автоматически включают:
- `client` - IP:port клиента
- `conn_id` - ID соединения
- `port` - целевой порт

### Интеграция с системами логирования

**С journald (systemd):**
```bash
journalctl --user -u fxtunnel -f
```

**С Docker:**
```bash
docker logs -f fxtunnel-server
```

**С Fluentd/Logstash:**
Используйте `--log-json` для структурированного вывода.

---

## Docker

### Сборка образа

```bash
docker build -t fxtunnel .
```

Характеристики образа:
- Multi-stage build
- Base: python:3.13-slim
- Размер: ~100MB
- Non-root user: fxtunnel

### Базовый запуск

```bash
docker run -d \
  --name fxtunnel-server \
  -p 9000:9000 \
  -p 8080:8080 \
  -v fxtunnel-data:/data \
  fxtunnel
```

### Docker Compose

**docker-compose.yml:**
```yaml
services:
  fxtunnel-server:
    build: .
    ports:
      - "9000:9000"
      - "8080:8080"
    volumes:
      - fxtunnel-data:/data
    restart: unless-stopped

volumes:
  fxtunnel-data:
```

**Команды:**
```bash
docker-compose up -d      # Запуск
docker-compose logs -f    # Логи
docker-compose down       # Остановка
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
  --cpus 0.5 \
  fxtunnel server \
  --health-port 8080 \
  --allowed-ports 5432,6379,80,443 \
  --max-clients 50 \
  --log-json
```

### Переменные окружения

| Переменная | Default | Описание |
|------------|---------|----------|
| `FXTUNNEL_DATA_DIR` | `/data` | Директория для ключей и конфига |
| `PYTHONUNBUFFERED` | `1` | Отключение буферизации вывода |

### Персистентность данных

**Важно**: всегда используйте volumes для `/data`!

Без volume при перезапуске:
- Сервер получит новый identity key
- Клиенты увидят "SERVER IDENTITY HAS CHANGED"
- Авторизация клиентов будет потеряна

**Named volume:**
```bash
-v fxtunnel-data:/data
```

**Bind mount:**
```bash
-v /host/path/fxtunnel:/data
```

### Kubernetes deployment

См. [docker/README.md](../docker/README.md) для полных примеров.

---

## Systemd

### Создание сервиса

**Копирование unit файла:**
```bash
mkdir -p ~/.config/systemd/user
cp ~/fxtunnel/systemd/fxtunnel.service ~/.config/systemd/user/
```

**Пример fxtunnel.service:**
```ini
[Unit]
Description=fxTunnel Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/user/fxtunnel/main.py server --health-port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

### Управление сервисом

```bash
# Перезагрузка конфигурации
systemctl --user daemon-reload

# Включение автозапуска
systemctl --user enable fxtunnel

# Запуск
systemctl --user start fxtunnel

# Статус
systemctl --user status fxtunnel

# Остановка
systemctl --user stop fxtunnel

# Логи
journalctl --user -u fxtunnel -f
```

### Запуск без логина

```bash
sudo loginctl enable-linger $USER
```

Это позволит сервису работать даже когда пользователь не залогинен.

### Настройка firewall

**UFW:**
```bash
sudo ufw allow 9000/tcp
sudo ufw allow 8080/tcp  # для health check
```

**firewalld:**
```bash
sudo firewall-cmd --add-port=9000/tcp --permanent
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload
```

---

## Продвинутое использование

### Кастомная директория данных

```bash
export FXTUNNEL_DATA_DIR=/custom/path
python main.py server
```

### Несколько серверов на одной машине

```bash
# Сервер 1
FXTUNNEL_DATA_DIR=~/.fxtunnel-1 python main.py server --port 9001

# Сервер 2
FXTUNNEL_DATA_DIR=~/.fxtunnel-2 python main.py server --port 9002
```

### Туннель через несколько хопов

```bash
# Машина A -> Машина B
python main.py client --ip machineB -L 9000:9000

# Машина B -> Машина C
python main.py client --ip machineC -L 5432:5432
```

### Скрипт для автозапуска нескольких туннелей

```bash
#!/bin/bash
# tunnels.sh

python main.py client --ip 192.168.1.100 \
  -L 5432:5432 \
  -L 6379:6379 \
  -L 8080:80 \
  --log-file ~/tunnel.log &

echo "Tunnels started. PID: $!"
```

### Использование с SSH ProxyJump

```bash
# SSH к серверу через jump host
ssh -J jumphost user@server

# Затем на server:
python main.py server

# На локальной машине:
python main.py client --ip server -L 5432:5432
```

### Мониторинг трафика

При завершении клиент выводит статистику:
```
Statistics: 10.50 MB sent, 25.30 MB received, 42 connections
```

Или через `/metrics` endpoint:
```bash
watch -n 5 'curl -s http://localhost:8080/metrics | jq'
```

---

## Устранение неполадок

### Клиент не подключается

**Проверка доступности сервера:**
```bash
nc -zv <server_ip> 9000
```

**Проверка firewall:**
```bash
sudo ss -tlnp | grep 9000
```

**Проверка процесса:**
```bash
ps aux | grep fxtunnel
```

### Authentication failed

**Причина**: ключ клиента не совпадает с authorized_key на сервере.

**Решение - сбросить авторизацию:**
```bash
# На сервере
rm ~/.fxtunnel/authorized_key
systemctl --user restart fxtunnel
```

### SERVER IDENTITY HAS CHANGED

**Причина**: fingerprint сервера изменился (переустановка, новый ключ).

**Решение:**
```bash
# На клиенте
nano ~/.fxtunnel/known_hosts
# Удалите строку с IP:PORT сервера
```

### Connection refused

**Причины:**
- Сервер не запущен
- Неправильный порт
- Firewall блокирует

**Проверка:**
```bash
systemctl --user status fxtunnel
sudo ss -tlnp | grep 9000
```

### Port already in use

**На клиенте:**
```bash
sudo lsof -i :5432
sudo ss -tlnp | grep 5432
```

**Решение**: выберите другой локальный порт:
```bash
python main.py client --ip server -L 15432:5432
```

### Port not allowed

**Причина**: порт не в списке allowed_ports на сервере.

**Решение**: добавьте порт в конфиг сервера:
```bash
python main.py server --allowed-ports 5432,6379,NEW_PORT
```

### Timeout errors

**Причины:**
- Сеть нестабильна
- Сервер перегружен

**Проверка:**
```bash
ping <server_ip>
```

Heartbeat отправляется каждые 15 секунд, timeout - 60 секунд.

### Debug режим

```bash
python main.py client --ip server -L 5432:5432 --verbose
```

Покажет детальную информацию о подключении, аутентификации и данных.

### Проверка логов

**Systemd:**
```bash
journalctl --user -u fxtunnel -f
```

**Docker:**
```bash
docker logs -f fxtunnel-server
```

**Файл:**
```bash
tail -f ~/fxtunnel.log
```

---

## Протокол и архитектура

### Формат сообщений

```
[4 bytes: length][encrypted payload]
```

**Payload после расшифровки:**
```
[1 byte: msg_type][4 bytes: conn_id][data]
```

### Типы сообщений

| Type | Значение | Описание |
|------|----------|----------|
| SERVER_IDENTITY | 0 | Fingerprint сервера |
| AUTH | 1 | Запрос аутентификации |
| AUTH_CHALLENGE | 2 | Challenge от сервера |
| AUTH_RESPONSE | 3 | HMAC ответ |
| AUTH_OK | 4 | Успешная аутентификация |
| AUTH_FAIL | 5 | Ошибка аутентификации |
| NEW_CONN | 20 | Новое соединение |
| CONN_CLOSED | 21 | Соединение закрыто |
| DATA | 30 | Данные |
| PING | 40 | Heartbeat ping |
| PONG | 41 | Heartbeat pong |
| SHUTDOWN | 50 | Graceful shutdown |

### Процесс подключения

1. **TCP connect**: клиент подключается к серверу
2. **Server identity**: сервер отправляет fingerprint
3. **Host verification**: клиент проверяет known_hosts
4. **Auth request**: клиент отправляет свой fingerprint
5. **Challenge**: сервер отправляет случайный challenge
6. **Response**: клиент отправляет HMAC(key, challenge)
7. **Verification**: сервер проверяет ответ
8. **Encryption**: включается AES-256-GCM
9. **Ready**: туннель готов к работе

### Шифрование

**AES-256-GCM:**
- Ключ: 256 бит (32 байта)
- Nonce: 96 бит (12 байт)
- Tag: 128 бит (16 байт)

Каждое сообщение шифруется со случайным nonce.

### Аутентификация

**HMAC-SHA256:**
```
response = HMAC-SHA256(shared_key, challenge)
```

Challenge: 256 бит (32 байта) случайных данных.

### Heartbeat

- Интервал: 15 секунд
- Timeout: 60 секунд
- При timeout соединение закрывается

### Reconnect

Exponential backoff с jitter:
```
delay = min(2^attempt, 30) + random(0, delay * 0.1)
```

---

## Справочник команд

### Все команды

```bash
# Сервер
python main.py server [options]

# Клиент
python main.py client --ip <server> -L <spec> [options]

# Профиль
python main.py connect <profile> [options]

# Конфигурация
python main.py config init [--force]
python main.py config show

# Статус
python main.py status

# Версия
python main.py --version

# Справка
python main.py --help
python main.py server --help
python main.py client --help
python main.py connect --help
```

### Примеры для разных сценариев

**PostgreSQL:**
```bash
python main.py client --ip db-server -L 5432:5432
psql -h localhost -U postgres
```

**Redis:**
```bash
python main.py client --ip redis-server -L 6379:6379
redis-cli
```

**Web-сервер:**
```bash
python main.py client --ip web-server -L 8080:80
curl http://localhost:8080
```

**DNS (UDP):**
```bash
python main.py client --ip dns-server -L 5353:53:udp
dig @localhost -p 5353 example.com
```

**Множественные сервисы:**
```bash
python main.py client --ip server \
  -L 5432:5432 \
  -L 6379:6379 \
  -L 8080:80 \
  -L 3000:3000
```

---

## Дополнительные ресурсы

- [README.md](../README.md) - Основная документация
- [docker/README.md](../docker/README.md) - Docker и Kubernetes
- [todo.md](../todo.md) - План развития проекта

---

## Поддержка

При возникновении проблем:

1. Проверьте раздел [Устранение неполадок](#устранение-неполадок)
2. Включите `--verbose` для детальных логов
3. Проверьте [GitHub Issues](https://github.com/user/fxtunnel/issues)
