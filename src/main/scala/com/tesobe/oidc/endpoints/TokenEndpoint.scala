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

class TokenEndpoint(
  authService: AuthService[IO],
  codeService: CodeService[IO], 
  jwtService: JwtService[IO],
  config: OidcConfig
) {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "token" =>
      req.as[UrlForm].flatMap(handleTokenRequest)
  }

  private def handleTokenRequest(form: UrlForm): IO[Response[IO]] = {
    val formData = form.values.mapValues(_.headOption.getOrElse(""))
    
    val grantType = formData.get("grant_type")
    val code = formData.get("code")
    val redirectUri = formData.get("redirect_uri")
    val clientId = formData.get("client_id")
    
    (grantType, code, redirectUri, clientId) match {
      case (Some("authorization_code"), Some(authCode), Some(redirectUriValue), Some(clientIdValue)) =>
        processAuthorizationCodeGrant(authCode, redirectUriValue, clientIdValue)
      case (Some(unsupportedGrant), _, _, _) =>
        BadRequest(OidcError("unsupported_grant_type", Some(s"Grant type '$unsupportedGrant' is not supported")).asJson)
      case _ =>
        BadRequest(OidcError("invalid_request", Some("Missing required parameters")).asJson)
    }
  }

  private def processAuthorizationCodeGrant(
    code: String,
    redirectUri: String, 
    clientId: String
  ): IO[Response[IO]] = {
    
    codeService.validateAndConsumeCode(code, clientId, redirectUri).flatMap {
      case Right(authCode) =>
        // Get user information
        authService.getUserById(authCode.sub).flatMap {
          case Some(user) =>
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
            BadRequest(OidcError("invalid_grant", Some("User not found")).asJson)
        }
        
      case Left(error) =>
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