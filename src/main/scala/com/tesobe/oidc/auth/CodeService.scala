/*
 * Copyright (c) 2025 TESOBE
 *
 * This file is part of OBP-OIDC.
 *
 * OBP-OIDC is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * OBP-OIDC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OBP-OIDC. If not, see <http://www.gnu.org/licenses/>.
 */

package com.tesobe.oidc.auth


import cats.effect.{IO, Ref}
import cats.syntax.either._
import com.tesobe.oidc.models.{AuthorizationCode, OidcError}
import com.tesobe.oidc.config.OidcConfig

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration._

trait CodeService[F[_]] {
  def generateCode(clientId: String, redirectUri: String, sub: String, scope: String, state: Option[String] = None, nonce: Option[String] = None): F[String]
  def validateAndConsumeCode(code: String, clientId: String, redirectUri: String): F[Either[OidcError, AuthorizationCode]]
}

class InMemoryCodeService(config: OidcConfig, codesRef: Ref[IO, Map[String, AuthorizationCode]]) extends CodeService[IO] {

  def generateCode(clientId: String, redirectUri: String, sub: String, scope: String, state: Option[String] = None, nonce: Option[String] = None): IO[String] = {
    for {
      code <- IO(UUID.randomUUID().toString.replace("-", ""))
      exp = Instant.now().plusSeconds(config.codeExpirationSeconds).getEpochSecond

      authCode = AuthorizationCode(
        code = code,
        client_id = clientId,
        redirect_uri = redirectUri,
        sub = sub,
        scope = scope,
        state = state,
        nonce = nonce,
        exp = exp
      )

      _ <- codesRef.update(_ + (code -> authCode))
    } yield code
  }

  def validateAndConsumeCode(code: String, clientId: String, redirectUri: String): IO[Either[OidcError, AuthorizationCode]] = {
    for {
      codes <- codesRef.get
      result <- codes.get(code) match {
        case Some(authCode) =>
          validateCode(authCode, clientId, redirectUri).flatMap {
            case Right(validCode) =>
              // Consume the code (remove it after use)
              codesRef.update(_ - code).as(validCode.asRight[OidcError])
            case Left(error) =>
              // Remove invalid code
              codesRef.update(_ - code).as(error.asLeft[AuthorizationCode])
          }
        case None =>
          IO.pure(OidcError("invalid_grant", Some("Authorization code not found")).asLeft[AuthorizationCode])
      }
    } yield result
  }

  private def validateCode(authCode: AuthorizationCode, clientId: String, redirectUri: String): IO[Either[OidcError, AuthorizationCode]] = {
    IO {
      val now = Instant.now().getEpochSecond

      if (authCode.exp < now) {
        OidcError("invalid_grant", Some("Authorization code expired")).asLeft[AuthorizationCode]
      } else if (authCode.client_id != clientId) {
        OidcError("invalid_grant", Some("Client ID mismatch")).asLeft[AuthorizationCode]
      } else if (authCode.redirect_uri != redirectUri) {
        OidcError("invalid_grant", Some("Redirect URI mismatch")).asLeft[AuthorizationCode]
      } else {
        authCode.asRight[OidcError]
      }
    }
  }

  // Helper method to clean up expired codes
  def cleanupExpiredCodes: IO[Unit] = {
    val now = Instant.now().getEpochSecond
    codesRef.update(_.filter(_._2.exp > now))
  }
}

object CodeService {
  def apply(config: OidcConfig): IO[CodeService[IO]] = {
    for {
      codesRef <- Ref.of[IO, Map[String, AuthorizationCode]](Map.empty)
    } yield new InMemoryCodeService(config, codesRef)
  }
}
