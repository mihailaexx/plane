# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import base64
import json
import os
from datetime import datetime
from urllib.parse import urlencode, urlparse

import pytz

from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)


class KeycloakOAuthProvider(OauthAdapter):
    """
    Keycloak OIDC provider following the same pattern as GiteaOAuthProvider.
    Uses a configurable server URL + realm to build OIDC endpoints.
    """

    provider = "keycloak"
    scope = "openid email profile"

    def __init__(self, request, code=None, state=None, callback=None):
        (KEYCLOAK_SERVER_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET) = (
            get_configuration_value(
                [
                    {
                        "key": "KEYCLOAK_SERVER_URL",
                        "default": os.environ.get("KEYCLOAK_SERVER_URL"),
                    },
                    {
                        "key": "KEYCLOAK_REALM",
                        "default": os.environ.get("KEYCLOAK_REALM"),
                    },
                    {
                        "key": "KEYCLOAK_CLIENT_ID",
                        "default": os.environ.get("KEYCLOAK_CLIENT_ID"),
                    },
                    {
                        "key": "KEYCLOAK_CLIENT_SECRET",
                        "default": os.environ.get("KEYCLOAK_CLIENT_SECRET"),
                    },
                ]
            )
        )

        if not (KEYCLOAK_SERVER_URL and KEYCLOAK_REALM and KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["KEYCLOAK_NOT_CONFIGURED"],
                error_message="KEYCLOAK_NOT_CONFIGURED",
            )

        # Enforce scheme and normalize
        parsed = urlparse(KEYCLOAK_SERVER_URL)
        if not parsed.scheme or parsed.scheme not in ("https", "http"):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["KEYCLOAK_NOT_CONFIGURED"],
                error_message="KEYCLOAK_NOT_CONFIGURED",
            )
        KEYCLOAK_SERVER_URL = KEYCLOAK_SERVER_URL.rstrip("/")

        # Build Keycloak OIDC endpoints from server URL + realm
        # Use an optional internal URL for server-side calls (Docker networking)
        internal_url = os.environ.get("KEYCLOAK_SERVER_INTERNAL_URL", "").rstrip("/") or KEYCLOAK_SERVER_URL
        base_oidc_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect"
        base_oidc_internal_url = f"{internal_url}/realms/{KEYCLOAK_REALM}/protocol/openid-connect"
        self.token_url = f"{base_oidc_internal_url}/token"
        self.userinfo_url = f"{base_oidc_internal_url}/userinfo"

        client_id = KEYCLOAK_CLIENT_ID
        client_secret = KEYCLOAK_CLIENT_SECRET

        redirect_uri = (
            f"{'https' if request.is_secure() else 'http'}://{request.get_host()}"
            f"/auth/keycloak/callback/"
        )
        url_params = {
            "client_id": client_id,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        auth_url = f"{base_oidc_url}/auth?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            client_secret,
            code,
            callback=callback,
        )

    def set_token_data(self):
        """Exchange authorization code for tokens."""
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        token_response = self.get_user_token(data=data)
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.fromtimestamp(
                        token_response.get("expires_in"), tz=pytz.utc
                    )
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.fromtimestamp(
                        token_response.get("refresh_token_expired_at"),
                        tz=pytz.utc,
                    )
                    if token_response.get("refresh_token_expired_at")
                    else None
                ),
                "id_token": token_response.get("id_token", ""),
            }
        )

    @staticmethod
    def _decode_id_token_claims(id_token):
        """Decode JWT payload without signature verification.
        The token was just received from Keycloak over TLS so
        cryptographic verification is unnecessary here."""
        try:
            payload_segment = id_token.split(".")[1]
            # Add padding if needed
            padding = 4 - len(payload_segment) % 4
            if padding != 4:
                payload_segment += "=" * padding
            return json.loads(base64.urlsafe_b64decode(payload_segment))
        except (IndexError, ValueError, json.JSONDecodeError):
            return {}

    def _check_required_role(self):
        """Reject the user if a required Keycloak role is configured
        and the user's id_token does not contain it."""
        (KEYCLOAK_REQUIRED_ROLE,) = get_configuration_value(
            [
                {
                    "key": "KEYCLOAK_REQUIRED_ROLE",
                    "default": os.environ.get("KEYCLOAK_REQUIRED_ROLE", ""),
                },
            ]
        )

        if not KEYCLOAK_REQUIRED_ROLE:
            return

        claims = self._decode_id_token_claims(
            self.token_data.get("id_token", "")
        )
        realm_roles = claims.get("realm_access", {}).get("roles", [])

        if KEYCLOAK_REQUIRED_ROLE not in realm_roles:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES[
                    "KEYCLOAK_ROLE_NOT_GRANTED"
                ],
                error_message="KEYCLOAK_ROLE_NOT_GRANTED",
            )

    def set_user_data(self):
        """Fetch user info from Keycloak userinfo endpoint."""
        user_info_response = self.get_user_response()
        email = user_info_response.get("email", "")

        if not email:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES[
                    "KEYCLOAK_OAUTH_PROVIDER_ERROR"
                ],
                error_message="KEYCLOAK_OAUTH_PROVIDER_ERROR",
            )

        # Gate: check required role before allowing login
        self._check_required_role()

        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": user_info_response.get("sub", ""),
                    "email": email,
                    "avatar": user_info_response.get("picture", ""),
                    "first_name": user_info_response.get("given_name", ""),
                    "last_name": user_info_response.get("family_name", ""),
                    "is_password_autoset": True,
                },
            }
        )
