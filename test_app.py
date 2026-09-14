import pytest

from app import app, setup_database


@pytest.fixture
def client(tmp_path):
    app.config["DATABASE"] = str(tmp_path / "test.db")
    setup_database()
    return app.test_client()


def register(client, user="alice", password="Password1!"):
    return client.post("/auth/register", json={"login": user, "password": password})


def do_login(client, user="alice", password="Password1!"):
    return client.post("/auth/login", json={"login": user, "password": password})


def token(client, user="alice", password="Password1!"):
    register(client, user, password)
    return do_login(client, user, password).get_json()["access_token"]


def auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_register_login_and_read_own_notes(client):
    tok = token(client)
    client.post("/api/data", json={"title": "first", "body": "hello"}, headers=auth(tok))

    response = client.get("/api/data", headers=auth(tok))
    assert response.status_code == 200
    assert response.get_json() == {"notes": [{"id": 1, "title": "first", "body": "hello"}]}


def test_data_requires_valid_token(client):
    assert client.get("/api/data").status_code == 401
    assert client.get("/api/data", headers=auth("not.a.token")).status_code == 401


def test_duplicate_login_rejected(client):
    register(client, "bob")
    assert register(client, "bob").status_code == 409


def test_short_password_rejected(client):
    assert register(client, "carol", "short").status_code == 400


def test_wrong_password_rejected(client):
    register(client, "dave")
    assert do_login(client, "dave", "WrongPass1!").status_code == 401


def test_sql_injection_does_not_bypass_login(client):
    register(client, "erin")
    assert do_login(client, "erin' --", "anything").status_code == 401
    assert do_login(client, "' OR '1'='1", "' OR '1'='1").status_code == 401


def test_note_content_is_escaped(client):
    tok = token(client, "frank")
    client.post(
        "/api/data",
        json={"title": "<script>alert(1)</script>", "body": "<img src=x onerror=alert(2)>"},
        headers=auth(tok),
    )

    body = client.get("/api/data", headers=auth(tok)).get_data(as_text=True)
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_users_cannot_read_each_others_notes(client):
    alice = token(client, "grace")
    bob = token(client, "heidi")
    client.post("/api/data", json={"title": "secret", "body": "private"}, headers=auth(alice))

    assert client.get("/api/data", headers=auth(bob)).get_json() == {"notes": []}
