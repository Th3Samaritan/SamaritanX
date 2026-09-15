"""Provision disposable ordinary users through the local shop's normal workflows."""
import os
import secrets
from pathlib import Path
import httpx
import yaml


class Identities:
    def __init__(self):
        self.environment = []
        self.recipes = []
        self.objects = []

    def prepare(self, origin, output):
        from urllib.parse import urlsplit
        if urlsplit(origin).hostname != "127.0.0.1":
            raise ValueError("lab setup is restricted to loopback")
        with httpx.Client(base_url=origin, trust_env=False, follow_redirects=False, timeout=10) as client:
            for index, label in enumerate(("user-a", "user-b")):
                email = "sx-" + secrets.token_hex(8) + "@example.invalid"
                password = secrets.token_urlsafe(24)
                response = client.post("/api/Users", json={"email": email, "password": password, "passwordRepeat": password})
                response.raise_for_status()
                response = client.post("/rest/user/login", json={"email": email, "password": password})
                response.raise_for_status()
                authentication = response.json()["authentication"]
                token, basket = authentication["token"], authentication["bid"]
                env = "SX_LAB_" + secrets.token_hex(12).upper()
                os.environ[env] = token
                self.environment.append(env)
                path = Path(output) / (label + ".yaml")
                path.write_text(yaml.safe_dump({"type": "static", "label": label,
                    "headers": {"Authorization": "Bearer {ENV:" + env + "}"}}), encoding="utf-8")
                self.recipes.append(path)
                response = client.post("/api/BasketItems", headers={"Authorization": "Bearer " + token},
                    json={"BasketId": basket, "ProductId": index + 1, "quantity": 1})
                response.raise_for_status()
                self.objects.append({"url": origin + "/rest/basket/" + str(basket), "owner": label,
                                     "role": "member", "denied_viewers": ["user-b" if index == 0 else "user-a"]})
        return self

    def close(self):
        for name in self.environment:
            os.environ.pop(name, None)
