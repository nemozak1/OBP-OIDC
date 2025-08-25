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

package com.tesobe.oidc.endpoints

import cats.effect.IO
import cats.syntax.all._
import com.tesobe.oidc.auth.{AuthService, CodeService}
import com.tesobe.oidc.models.{OidcError, TokenRequest, TokenResponse}
import com.tesobe.oidc.tokens.JwtService
import com.tesobe.oidc.config.OidcConfig
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.typelevel.ci.CIString
import org.http4s.dsl.io._
import org.slf4j.LoggerFactory

class TokenEndpoint(
  authService: AuthService[IO],
  codeService: CodeService[IO],
  jwtService: JwtService[IO],
  config: OidcConfig
) {

  private val logger = LoggerFactory.getLogger(getClass)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "obp-oidc" / "token" =>
      println(s"🎫 DEBUG: TokenEndpoint route matched! ${req.method} ${req.uri}")
      println(s"🎫 DEBUG: About to log with logger...")
      logger.info(s"🎫 Token endpoint called")
      logger.info(s"📋 Content-Type: ${req.headers.get[headers.`Content-Type`].map(_.mediaType).getOrElse("MISSING")}")
      logger.info(s"🔗 Headers: ${req.headers.headers.map(h => s"${h.name}: ${h.value}").mkString(", ")}")
      println(s"🎫 DEBUG: Logger calls completed, about to parse form...")

      req.as[UrlForm].attempt.flatMap {
        case Right(form) =>
          println(s"🎫 DEBUG: Form parsing successful")
          println(s"🎫 DEBUG: Form data: ${form.values}")
          handleTokenRequest(form)
        case Left(error) =>
          println(s"💥 DEBUG: Form parsing failed: ${error.getMessage}")
          logger.error(s"💥 Failed to parse form data: ${error.getMessage}", error)
          BadRequest(OidcError("invalid_request", Some("Failed to parse form data")).asJson)
      }


  }

  private def handleTokenRequest(form: UrlForm): IO[Response[IO]] = {
    println(s"🎫 DEBUG: handleTokenRequest called")
    val formData = form.values.mapValues(_.headOption.getOrElse(""))
    println(s"🎫 DEBUG: formData created: ${formData}")

    logger.info(s"🎫 Token request received")
    logger.info(s"📋 Form data keys: ${formData.keys.mkString(", ")}")

    val grantType = formData.get("grant_type")
    val code = formData.get("code")
    val redirectUri = formData.get("redirect_uri")
    val clientId = formData.get("client_id")

    println(s"🎫 DEBUG: Grant type extracted: ${grantType}")
    logger.info(s"🔑 Grant type: ${grantType.getOrElse("MISSING")}")
    logger.info(s"🎟️ Code: ${code.map(_ => "PROVIDED").getOrElse("MISSING")}")
    logger.info(s"📍 Redirect URI: ${redirectUri.getOrElse("MISSING")}")
    logger.info(s"🆔 Client ID: ${clientId.getOrElse("MISSING")}")

    println(s"🎫 DEBUG: About to match on parameters")
    (grantType, code, redirectUri, clientId) match {
      case (Some("authorization_code"), Some(authCode), Some(redirectUriValue), Some(clientIdValue)) =>
        println(s"🎫 DEBUG: Matched authorization_code case")
        logger.info(s"✅ Processing authorization_code grant for client: $clientIdValue")
        processAuthorizationCodeGrant(authCode, redirectUriValue, clientIdValue)
      case (Some(unsupportedGrant), _, _, _) =>
        println(s"🎫 DEBUG: Matched unsupported grant type case: '$unsupportedGrant'")
        logger.warn(s"❌ Unsupported grant type: '$unsupportedGrant'")
        BadRequest(OidcError("unsupported_grant_type", Some(s"Grant type '$unsupportedGrant' is not supported")).asJson)
      case _ =>
        println(s"🎫 DEBUG: Matched missing parameters case")
        logger.warn(s"❌ Missing required parameters - grant_type: ${grantType.isDefined}, code: ${code.isDefined}, redirect_uri: ${redirectUri.isDefined}, client_id: ${clientId.isDefined}")
        BadRequest(OidcError("invalid_request", Some("Missing required parameters")).asJson)
    }
  }

  private def processAuthorizationCodeGrant(
    code: String,
    redirectUri: String,
    clientId: String
  ): IO[Response[IO]] = {

    logger.info(s"🔍 Validating authorization code for client: $clientId")
    codeService.validateAndConsumeCode(code, clientId, redirectUri).flatMap {
      case Right(authCode) =>
        logger.info(s"✅ Authorization code validated for user: ${authCode.sub}")
        // Get user information
        authService.getUserById(authCode.sub).flatMap {
          case Some(user) =>
            logger.info(s"✅ User found: ${user.username}, generating tokens...")
            for {
              // Generate tokens
              idToken <- jwtService.generateIdToken(user, clientId, authCode.nonce)
              accessToken <- jwtService.generateAccessToken(user, clientId, authCode.scope)

              // Create token response
              tokenResponse = TokenResponse(
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = config.tokenExpirationSeconds,
                id_token = idToken,
                scope = authCode.scope
              )

              response <- Ok(tokenResponse.asJson)
                .map(_.withHeaders(
                  Header.Raw(CIString("Cache-Control"), "no-store"),
                  Header.Raw(CIString("Pragma"), "no-cache")
                ))

            } yield response

          case None =>
            logger.warn(s"❌ User not found for sub: ${authCode.sub}")
            BadRequest(OidcError("invalid_grant", Some("User not found")).asJson)
        }

      case Left(error) =>
        logger.warn(s"❌ Authorization code validation failed: ${error.error} - ${error.error_description.getOrElse("No description")}")
        BadRequest(error.asJson)
    }
  }
}

object TokenEndpoint {
  def apply(
    authService: AuthService[IO],
    codeService: CodeService[IO],
    jwtService: JwtService[IO],
    config: OidcConfig
  ): TokenEndpoint =
    new TokenEndpoint(authService, codeService, jwtService, config)
}
