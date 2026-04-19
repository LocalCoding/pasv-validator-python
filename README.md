# pasv-validator-python

Сервис валидации Python-решений студентов PASV. Зеркалит API `pasv-validator` (JS), но для Python.

## Архитектура

```
Client → Backend → pasv-validator-python → (callback) → Backend
```

Backend выбирает URL по `programmingLang`:
- `JavaScript`/`Java` → `DOCKERIZED_VALIDATOR_URL` (https://validator.pasv.us)
- `Python` → `DOCKERIZED_VALIDATOR_PYTHON_URL` (https://validator-py.pasv.us)

## API

### `GET /test`
Healthcheck.

### `POST /validate/unit/place`
Body: `{ solution, test, userId, challengeId, programmingLang: "Python" }`

- `solution` — код студента (Python)
- `test` — `class TestClass*: def test_N(self):` и/или `def test_*():` (pytest-style)

Отвечает мгновенно `200 OK`, результат уходит на backend через callback асинхронно.

## Формат тестов

Совместим с существующими задачами из курса Python Syntax в БД:

**Классы (76 из 82 задач):**
```python
class TestClass(object):
    def test_1(self):
        """Title shown to student"""
        assert x == 10
```

**Функции:**
```python
def test_average():
    assert average([1, 2, 3]) == 2
```

## Sandbox

- subprocess с `resource.setrlimit`: CPU 10s, память 256 MB, файлы 64, размер файла 1 MB
- Wall timeout 12s (жёстче CPU — против sleep-ов)
- `os.setsid()` + `-I` (isolated mode) у Python
- Сеть изолируется на уровне Docker (`--network none` в проде)

## Запуск

```bash
pip install -r requirements.txt
NODE_ENV=local python -m uvicorn src.main:app --reload --port 7001
```

## Тесты

```bash
python -m pytest tests/ -v
```
