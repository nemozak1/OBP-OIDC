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
import com.tesobe.oidc.models.{AuthorizationRequest, LoginForm, OidcError}
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import org.http4s.headers.Location
import org.slf4j.LoggerFactory

class AuthEndpoint(authService: AuthService[IO], codeService: CodeService[IO]) {

  private val logger = LoggerFactory.getLogger(getClass)

  // Test logging immediately when class is created
  logger.info("🚀 AuthEndpoint created - logging is working!")
  println("🚀 AuthEndpoint created - logging is working!")

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "obp-oidc" / "auth" :?
      ResponseTypeQueryParamMatcher(responseType) +&
      ClientIdQueryParamMatcher(clientId) +&
      RedirectUriQueryParamMatcher(redirectUri) +&
      ScopeQueryParamMatcher(scope) +&
      StateQueryParamMatcher(state) +&
      NonceQueryParamMatcher(nonce) =>
      handleAuthorizationRequest(responseType, clientId, redirectUri, scope, state, nonce)

    case req @ POST -> Root / "obp-oidc" / "auth" =>
      req.as[UrlForm].flatMap(handleLoginSubmission)
  }

  // Query parameter matchers
  object ResponseTypeQueryParamMatcher extends QueryParamDecoderMatcher[String]("response_type")
  object ClientIdQueryParamMatcher extends QueryParamDecoderMatcher[String]("client_id")
  object RedirectUriQueryParamMatcher extends QueryParamDecoderMatcher[String]("redirect_uri")
  object ScopeQueryParamMatcher extends QueryParamDecoderMatcher[String]("scope")
  object StateQueryParamMatcher extends OptionalQueryParamDecoderMatcher[String]("state")
  object NonceQueryParamMatcher extends OptionalQueryParamDecoderMatcher[String]("nonce")

  private def handleAuthorizationRequest(
    responseType: String,
    clientId: String,
    redirectUri: String,
    scope: String,
    state: Option[String],
    nonce: Option[String]
  ): IO[Response[IO]] = {

    // Validate request parameters
    if (responseType != "code") {
      val error = OidcError("unsupported_response_type", Some("Only 'code' response type is supported"), state = state)
      redirectWithError(redirectUri, error)
    } else if (!scope.contains("openid")) {
      val error = OidcError("invalid_scope", Some("'openid' scope is required"), state = state)
      redirectWithError(redirectUri, error)
    } else {
      // Validate client and redirect URI
      authService.validateClient(clientId, redirectUri).flatMap { isValid =>
        if (!isValid) {
          val error = OidcError("invalid_client", Some("Invalid client_id or redirect_uri"), state = state)
          redirectWithError(redirectUri, error)
        } else {
          // Show login form
          showLoginForm(clientId, redirectUri, scope, state, nonce)
        }
      }
    }
  }

  private def handleLoginSubmission(form: UrlForm): IO[Response[IO]] = {
    val formData = form.values.mapValues(_.headOption.getOrElse(""))

    for {
      _ <- IO(logger.info("🔥 LOGIN FORM SUBMISSION STARTED"))
      _ <- IO(println("🔥 LOGIN FORM SUBMISSION STARTED"))
      username <- IO.fromOption(formData.get("username"))(new RuntimeException("Missing username"))
      _ <- IO(logger.info(s"📋 Auth form submitted for username: '$username'"))
      _ <- IO(println(s"📋 Auth form submitted for username: '$username'"))
      password <- IO.fromOption(formData.get("password"))(new RuntimeException("Missing password"))
      _ <- IO(logger.debug(s"🔑 Password received (length: ${password.length})"))
      provider <- IO.fromOption(formData.get("provider"))(new RuntimeException("Missing provider"))
      _ <- IO(logger.info(s"🏢 Provider selected: '$provider'"))
      clientId <- IO.fromOption(formData.get("client_id"))(new RuntimeException("Missing client_id"))
      redirectUri <- IO.fromOption(formData.get("redirect_uri"))(new RuntimeException("Missing redirect_uri"))
      scope <- IO.fromOption(formData.get("scope"))(new RuntimeException("Missing scope"))
      state = formData.get("state")
      nonce = formData.get("nonce")

      _ <- IO(logger.info(s"🔄 Calling authentication service for username: '$username' with provider: '$provider'"))
      response <- authenticateAndGenerateCode(username, password, provider, clientId, redirectUri, scope, state, nonce)
    } yield response
  }.handleErrorWith { error =>
    logger.error(s"💥 Error handling login submission: ${error.getMessage}", error)
    BadRequest("Invalid form data")
  }

  private def authenticateAndGenerateCode(
    username: String,
    password: String,
    provider: String,
    clientId: String,
    redirectUri: String,
    scope: String,
    state: Option[String],
    nonce: Option[String]
  ): IO[Response[IO]] = {

    authService.authenticate(username, password, provider).flatMap {
      case Right(user) =>
        for {
          code <- codeService.generateCode(clientId, redirectUri, user.sub, scope, state, nonce)
          response <- redirectWithCode(redirectUri, code, state)
        } yield response

      case Left(error) =>
        redirectWithError(redirectUri, error.copy(state = state))
    }
  }

  private def showLoginForm(
    clientId: String,
    redirectUri: String,
    scope: String,
    state: Option[String],
    nonce: Option[String]
  ): IO[Response[IO]] = {

    authService.getAvailableProviders().flatMap { providers =>
      val stateParam = state.map(s => s"""<input type="hidden" name="state" value="$s">""").getOrElse("")
      val nonceParam = nonce.map(n => s"""<input type="hidden" name="nonce" value="$n">""").getOrElse("")

      val providerOptions = providers.map { provider =>
        s"""<option value="$provider">$provider</option>"""
      }.mkString("\n            ")

      val html = s"""
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login - OIDC Provider</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
          .form-group { margin-bottom: 15px; }
          label { display: block; margin-bottom: 5px; font-weight: bold; }
          input[type="text"], input[type="password"] {
            width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;
          }
          button {
            background: #007bff; color: white; padding: 10px 20px;
            border: none; border-radius: 4px; cursor: pointer; width: 100%;
          }
          button:hover { background: #0056b3; }
          .info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }

        </style>
      </head>
      <body>
        <h2>Sign In</h2>
        <div class="info">
          <strong>Client:</strong> $clientId<br>
          <strong>Requested Scopes:</strong> $scope
        </div>

        <form method="post" action="/obp-oidc/auth">
          <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
          </div>

          <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
          </div>

          <div class="form-group">
            <label for="provider">Authentication Provider:</label>
            <select id="provider" name="provider" required>
            $providerOptions
            </select>
          </div>

          <input type="hidden" name="client_id" value="$clientId">
          <input type="hidden" name="redirect_uri" value="$redirectUri">
          <input type="hidden" name="scope" value="$scope">
          $stateParam
          $nonceParam

          <button type="submit">Sign In</button>
        </form>
      </body>
      </html>
    """

      Ok(html).map(_.withContentType(org.http4s.headers.`Content-Type`(MediaType.text.html)))
    }
  }

  private def redirectWithCode(redirectUri: String, code: String, state: Option[String]): IO[Response[IO]] = {
    val stateParam = state.map(s => s"&state=$s").getOrElse("")
    val location = s"$redirectUri?code=$code$stateParam"
    SeeOther(Location(Uri.unsafeFromString(location)))
  }

  private def redirectWithError(redirectUri: String, error: OidcError): IO[Response[IO]] = {
    val stateParam = error.state.map(s => s"&state=$s").getOrElse("")
    val descriptionParam = error.error_description.map(d => s"&error_description=${java.net.URLEncoder.encode(d, "UTF-8")}").getOrElse("")
    val location = s"$redirectUri?error=${error.error}$descriptionParam$stateParam"
    SeeOther(Location(Uri.unsafeFromString(location)))
  }
}

object AuthEndpoint {
  def apply(authService: AuthService[IO], codeService: CodeService[IO]): AuthEndpoint =
    new AuthEndpoint(authService, codeService)
}
