# Kaspersky SafeBoard
### Необходимо реализовать веб сервер с REST-интерфейсом для обмена информацией про угрозы на основе OpenAPI спецификации. Перед реализацией необходимо дополнить модель угрозы полями.

## Реализация

Сервис на Go 1.24: HTTP API для обмена информацией об угрозах и in-memory хранилище.
Актуальный контракт — [openapi.yaml](openapi.yaml), архитектура и принятые решения — [docs/architecture.md](docs/architecture.md).

### Быстрый старт

```bash
make run          # http://localhost:8080
make test         # все тесты
make test-race    # тесты с race detector
make lint         # golangci-lint
```

Запуск в Docker:

```bash
make docker-up
curl http://localhost:8080/health
docker compose logs -f
make docker-down
```

В контейнере адрес переопределяется на `0.0.0.0:8080`, иначе порт не будет доступен с хоста.

### Маршруты

| Метод | Путь | Успех | Ошибки |
|---|---|---|---|
| `GET` | `/info/{md5}` | `200` | `400`, `404`, `500` |
| `PUT` | `/info/{md5}` | `200` | `400`, `404`, `413`, `415`, `500` |
| `POST` | `/info` | `201` | `400`, `409`, `413`, `415`, `500` |
| `GET` | `/health` | `200` | — |

`POST` и `PUT` принимают только `Content-Type: application/json`. Лимит тела — 1 MiB по умолчанию. Ошибки возвращаются в формате `{"message": "...", "details": "..."}`. `/health` — служебный эндпоинт для Docker healthcheck.

### Конфигурация

Настройки читаются из `cmd/server/config.yaml`, переменные окружения имеют приоритет.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `API_ADDRESS` | `localhost:8080` | адрес HTTP-сервера |
| `LOG_LEVEL` | `DEBUG` | `DEBUG`, `INFO`, `ERROR` |
| `BODY_LIMIT` | `1048576` | максимальный размер тела, байт |
| `API_SHUTDOWN_TIMEOUT` | `8s` | таймаут graceful shutdown |

Остальные таймауты (`read_timeout`, `write_timeout`, `idle_timeout` и т.д.) — в `cmd/server/config.yaml`.

Данные хранятся в памяти: после перезапуска сервиса записи теряются.

---

Ниже — исходная постановка задачи. Актуальная спецификация — в [openapi.yaml](openapi.yaml).

### Начальный openapi:
```
openapi: 3.0.0
info:
  title: Information Exchange Service
  description: API для обмена информацией об угрозах. 
  version: 1.0.0

paths:
  /info/{md5}:
    get:
      summary: Получить информацию об угрозе по MD5
      description: Возвращает полную информацию об угрозе для указанного MD5-хеша.
      operationId: getInfoByMd5
      parameters:
        - name: md5
          in: path
          required: true
          description: MD5-хеш файла (32 символа, шестнадцатеричные цифры)
          schema:
            type: string
            pattern: '^[a-fA-F0-9]{32}$'
            example: "d41d8cd98f00b204e9800998ecf8427e"
      responses:
        '200':
          description: Успешный ответ с информацией об угрозе
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ThreatResponse'
        '404':
          description: Угроза с указанным MD5 не найден
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '400':
          description: Некорректный формат MD5
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Внутренняя ошибка сервера
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

    put:
      summary: Обновить информацию об угрозе по MD5
      description: Заменяет информацию о существующей угрозе
      operationId: updateThreat
      parameters:
        - name: md5
          in: path
          required: true
          description: MD5-хеш обновляемой записи
          schema:
            type: string
            pattern: '^[a-fA-F0-9]{32}$'
            example: "d41d8cd98f00b204e9800998ecf8427e"
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ThreatUpdateRequest'
      responses:
        '200':
          description: Информация успешно обновлена
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ThreatResponse'
        '400':
          description: Некорректные данные запроса или MD5
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '404':
          description: Угроза с указанным MD5 не найден
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Внутренняя ошибка сервера
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  /info:
    post:
      summary: Создать новую запись об угрозе
      description: Добавляет новую информацию об угрозе. MD5 должен быть уникальным.
      operationId: createThreat
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ThreatCreateRequest'
      responses:
        '201':
          description: Запись успешно создана
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ThreatResponse'
        '400':
          description: Некорректные данные запроса (например, невалидный MD5)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '409':
          description: Угроза с таким MD5 уже существует
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Внутренняя ошибка сервера
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

components:
  schemas:
    ThreatCreateRequest:
      type: object
      required:
        - md5
        - name
      properties:
        md5:
          type: string
          pattern: '^[a-fA-F0-9]{32}$'
          description: MD5-хеш файла (32 шестнадцатеричных символа)
          example: "d41d8cd98f00b204e9800998ecf8427e"
        name:
          type: string
          description: Название угрозы
          example: "Trojan.Win32.Generic"
    ThreatUpdateRequest:
      type: object
      required:
        - name
      properties:
        name:
          type: string
          description: Название угрозы
          example: "Trojan.Win32.Generic"
        
    ThreatResponse:
      type: object
      properties:
        md5:
          type: string
          pattern: '^[a-fA-F0-9]{32}$'
          description: MD5-хеш
          example: "d41d8cd98f00b204e9800998ecf8427e"
        name:
          type: string
          description: Название угрозы
          example: "Trojan.Win32.Generic"

    ErrorResponse:
      type: object
      properties:
        message:
          type: string
          description: Человекочитаемое описание ошибки
          example: "Threat not found"
        details:
          type: string
          description: Дополнительная информация
          example: "No threat with MD5 d41d8cd98f00b204e9800998ecf8427e found"
```

### Задание предполагает только реализацию сервиса, но будет плюсом:
1. Наличие юнит и интеграционных тестов
2. Осмысленное дополнение полей, валидация данных
3. Использование docker для развертывания
4. Использование СУБД и библиотек кодогенерации по спеке
5. Документация кода
6. Дополнительная защита сервиса (работа с сертификатами, rate-limit, управление доступом и т.д)

### Мои дополнения - см openapi.yaml

1. name без ограничений. "" и "   " валидны по спеке - сервер будет отдавать 400 на то, что спека разрешает.
2. tags: нет uniqueItems, а pattern: '\S' пропускает "  a  ". Дубликаты удаляются, краевые пробелы обрезаются.
3. - Добавил 413 при превышении лимита тела.
   - Добавил 415 при провале проверки на Content-Type.
4. Добавил служебный `GET /health` (вне исходной спеки) — используется Docker healthcheck.
5. Хранилище in-memory: после перезапуска сервиса данные теряются.