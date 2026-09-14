# Защищённый REST API

Лабораторная работа №1 по информационной безопасности. Небольшой сервис заметок на Flask:
регистрация, вход по JWT и доступ к своим заметкам только с валидным токеном. На каждый push и
pull request в GitHub Actions прогоняются тесты, статический анализ кода (SAST) и проверка
зависимостей (SCA).

## Стек

- Python 3.12, Flask
- SQLite (файл `notes.db`)
- PyJWT — токены, bcrypt — хеширование паролей, markupsafe — экранирование вывода
- bandit (SAST) и pip-audit (SCA) в CI

## Запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Сервис поднимается на `http://localhost:5001`, база создаётся автоматически. Секрет для подписи
токенов берётся из переменной окружения `JWT_SECRET` (если не задана, генерируется случайный на время
запуска). Тесты — `pytest`.

## API

| Метод | Путь | Доступ | Описание |
|-------|------|--------|----------|
| POST | `/auth/register` | все | регистрация |
| POST | `/auth/login` | все | вход, возвращает JWT |
| GET | `/api/data` | по токену | свои заметки |
| POST | `/api/data` | по токену | создать заметку |

### Регистрация

```bash
curl -X POST http://localhost:5001/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"login": "student", "password": "S3cretPass!"}'
# 201 {"id": 1, "login": "student"}
```

Логин 3–32 символа, пароль 8–72 байта. Если логин занят — `409`, при неверных данных — `400`.

### Вход

```bash
curl -X POST http://localhost:5001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login": "student", "password": "S3cretPass!"}'
# 200 {"access_token": "eyJhbGciOi..."}
```

Неверный логин или пароль — `401`.

### Заметки

```bash
curl http://localhost:5001/api/data -H "Authorization: Bearer <access_token>"
# 200 {"notes": [...]}

curl -X POST http://localhost:5001/api/data -H "Authorization: Bearer <access_token>" \
  -H 'Content-Type: application/json' -d '{"title": "Первая", "body": "текст"}'

curl http://localhost:5001/api/data
# 401 {"error": "Authorization token required"}
```

## Меры защиты

### SQL-инъекции

Все запросы к базе параметризованные: в SQL стоят плейсхолдеры `?`, значения передаются отдельным
аргументом, строки не склеиваются:

```python
db().execute("SELECT id, password_hash FROM users WHERE login = ?", (login,))
```

Драйвер SQLite подставляет значение как данные, а не как часть запроса, поэтому ввод вида
`' OR '1'='1` просто ищется как логин и ничего не находит.

### XSS

Пользовательские данные (логин, заголовок и текст заметки) экранируются через `markupsafe.escape`
перед выдачей в ответе. Логин `<script>alert(1)</script>` вернётся как
`&lt;script&gt;alert(1)&lt;/script&gt;` и в браузере не выполнится.

### Аутентификация

- **Пароли** хешируются bcrypt со случайной солью, в базе только хеш. bcrypt намеренно медленный,
  поэтому перебор по украденной базе дорогой.
- **JWT.** После входа выдаётся токен HS256 с id пользователя (`sub`), временем выдачи (`iat`) и
  сроком действия (`exp`, 1 час). Секрет подписи — в переменной окружения, в коде его нет.
- **Проверка токена.** Декоратор `authenticated` стоит на `/api/data`: проверяет заголовок
  `Authorization: Bearer <token>`, подпись и срок действия. Разрешён только HS256, поэтому токен с
  `alg: none` не пройдёт. Нет токена или он невалиден — `401`.
- **Изоляция данных.** id пользователя берётся из токена, запрос заметок идёт с условием
  `owner_id = ?`, поэтому чужие заметки увидеть нельзя.

## CI/CD

Файл `.github/workflows/ci.yml`, запускается на каждый push и pull request:

1. `pytest` — тесты API (вход, доступ без токена, дубль логина, короткий пароль, SQL-инъекция, XSS,
   изоляция заметок).
2. **SAST** — `bandit -r app.py`, статический анализ кода на уязвимости.
3. **SCA** — `pip-audit -r requirements.txt`, проверка зависимостей по базе известных уязвимостей.

Если любая проверка падает — pipeline красный.
