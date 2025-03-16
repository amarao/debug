#!/usr/bin/python3
"""
    Script to get GHS token using Github App token

    Application is 'installed' into target repositories
    (there is no code, just an account with tightly scoped permissions)
    It uses special private key (APP_PRIVATE_KEY)
    to create JWT token, which, in turn, is used to get GHS-token
    (suitable for clone action)

    Token is passed via github 'outputs' mechainsm and marked
    as 'masked' (it would be masked from logs by '***').

    This script needs some github settings to work:
    application must be installed in all repositories to clone,
    a proper APP_ID and a valid APP_PRIVATE_KEY should be passed
    as environment variables.
"""


import jwt
import time
import requests
import os
import sys


def make_jwt_token(private_key, app_id):
    jwt_payload = {
        "iat": int(time.time()),
        "exp": int(time.time() + 600),
        "iss": int(app_id),
    }
    print("Getting app JWT")
    jwt_token = jwt.encode(jwt_payload, private_key, algorithm="RS256")
    if isinstance(jwt_token, bytes):
        jwt_token = jwt_token.decode()
    print("Got app JWT")
    return jwt_token


def get_installation_id(jwt_token):
    return requests.get(
        "https://api.github.com/app/installations",
        headers={"Authorization": f"Bearer {jwt_token}"},
    ).json()[0]["id"]


def get_token(jwt_token, installation_id):
    print("Getting bot access token")
    token = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={"Authorization": f"Bearer {jwt_token}"},
    ).json()["token"]
    print("Got bot access token")
    return token


def mask(value):
    if not os.environ.get("GITHUB_ACTIONS"):
        print("error: GITHUB_ACTIONS is not detected", file=sys.stderr)
        sys.exit(1)
    print(f"::add-mask::{value}")


def set_output(key, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if not output_file:
        print("Unable to get GITHUB_OUTPUT file name")
        sys.exit(1)
    with open(output_file, "ta") as f:
        f.write(f"{key}={value}\n")


def main():
    private_key = os.environ["APP_PRIVATE_KEY"]
    app_id = os.environ["APP_ID"]
    jwt_token = make_jwt_token(private_key, app_id)
    ghs_token = get_token(jwt_token, get_installation_id(jwt_token))
    mask(ghs_token)
    set_output("ghs_token", ghs_token)


if __name__ == "__main__":
    main()
