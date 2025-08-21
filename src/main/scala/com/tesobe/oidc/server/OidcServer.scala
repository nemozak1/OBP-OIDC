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

package com.tesobe.oidc.server

import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all._
import com.comcast.ip4s.{Host, Port}
import com.tesobe.oidc.auth.{CodeService, DatabaseAuthService}
import com.tesobe.oidc.config.Config
import com.tesobe.oidc.endpoints._
import com.tesobe.oidc.tokens.JwtService
import org.http4s._
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._
import cats.implicits._
import cats.kernel.Semigroup
import cats.syntax.semigroup._
import org.http4s.server.Router
import org.slf4j.LoggerFactory

object OidcServer extends IOApp {
  
  private val logger = LoggerFactory.getLogger(getClass)

  def run(args: List[String]): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(logger.info(s"Starting OIDC Provider on ${config.server.host}:${config.server.port}"))
      _ <- IO(logger.info(s"Issuer: ${config.issuer}"))
      
      // Test database connection
      _ <- DatabaseAuthService.testConnection(config).flatMap {
        case Right(msg) => IO(logger.info(msg))
        case Left(error) => IO.raiseError(new RuntimeException(s"Database connection failed: $error"))
      }
      
      exitCode <- DatabaseAuthService.create(config).use { authService =>
        for {
          // Initialize services
          codeService <- CodeService(config)
          jwtService <- JwtService(config)
        
          // Initialize endpoints
          discoveryEndpoint = DiscoveryEndpoint(config)
          jwksEndpoint = JwksEndpoint(jwtService)
          authEndpoint = AuthEndpoint(authService, codeService)
          tokenEndpoint = TokenEndpoint(authService, codeService, jwtService, config)
          userInfoEndpoint = UserInfoEndpoint(authService, jwtService)
          
          // Use Router with individual path mappings
          routes = Router(
            "/" -> discoveryEndpoint.routes,
            "/" -> jwksEndpoint.routes,
            "/" -> authEndpoint.routes,
            "/" -> tokenEndpoint.routes,
            "/" -> userInfoEndpoint.routes,
            "/" -> healthCheckRoutes
          ).orNotFound
          
          // Start server
          host <- IO.fromOption(Host.fromString(config.server.host))(
            new RuntimeException(s"Invalid host: ${config.server.host}")
          )
          port <- IO.fromOption(Port.fromInt(config.server.port))(
            new RuntimeException(s"Invalid port: ${config.server.port}")
          )
          
          _ <- EmberServerBuilder.default[IO]
            .withHost(host)
            .withPort(port)
            .withHttpApp(routes)
            .build
            .use { server =>
              IO(logger.info(s"OIDC Provider started at ${server.baseUri}")) *>
              IO(logger.info("Available endpoints:")) *>
              IO(logger.info(s"  Discovery: ${server.baseUri}/.well-known/openid-configuration")) *>
              IO(logger.info(s"  Authorization: ${server.baseUri}/auth")) *>
              IO(logger.info(s"  Token: ${server.baseUri}/token")) *>
              IO(logger.info(s"  UserInfo: ${server.baseUri}/userinfo")) *>
              IO(logger.info(s"  JWKS: ${server.baseUri}/jwks")) *>
              IO(logger.info(s"  Health Check: ${server.baseUri}/health")) *>
              IO.never
            }
        } yield ExitCode.Success
      }
    } yield exitCode
  }.handleErrorWith { error =>
    IO(logger.error("Failed to start OIDC Provider", error)) >>
    IO.pure(ExitCode.Error)
  }

  // Simple health check endpoint
  private val healthCheckRoutes: HttpRoutes[IO] = {
    import org.http4s.dsl.io._
    HttpRoutes.of[IO] {
      case GET -> Root / "health" =>
        Ok("OIDC Provider is running")
      case GET -> Root =>
        Ok("""
          |<!DOCTYPE html>
          |<html>
          |<head>
          |  <title>OBP OIDC Provider</title>
          |  <style>
          |    body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
          |    .endpoint { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
          |    .method { font-weight: bold; color: #007bff; }
          |    pre { background: #f1f1f1; padding: 10px; border-radius: 3px; overflow-x: auto; }
          |  </style>
          |</head>
          |<body>
          |  <h1>OBP OIDC Provider</h1>
          |  <p>A bare bones OpenID Connect provider built with http4s and functional programming.</p>
          |  
          |  <h2>Available Endpoints</h2>
          |  
          |  <div class="endpoint">
          |    <div class="method">GET</div>
          |    <strong>/.well-known/openid-configuration</strong>
          |    <p>OIDC Discovery document</p>
          |  </div>
          |  
          |  <div class="endpoint">
          |    <div class="method">GET</div>
          |    <strong>/auth</strong>
          |    <p>Authorization endpoint (with query parameters)</p>
          |  </div>
          |  
          |  <div class="endpoint">
          |    <div class="method">POST</div>
          |    <strong>/token</strong>
          |    <p>Token endpoint for authorization code exchange</p>
          |  </div>
          |  
          |  <div class="endpoint">
          |    <div class="method">GET/POST</div>
          |    <strong>/userinfo</strong>
          |    <p>UserInfo endpoint (requires Bearer token)</p>
          |  </div>
          |  
          |  <div class="endpoint">
          |    <div class="method">GET</div>
          |    <strong>/jwks</strong>
          |    <p>JSON Web Key Set for token verification</p>
          |  </div>
          |  
          |  <h2>Database Users</h2>
          |  <p>This OIDC provider authenticates against the PostgreSQL view <code>v_authuser_oidc</code>.</p>
          |  <p>Use any validated user from your OBP database to test authentication.</p>
          |  
          |  <h2>Example Authorization URL</h2>
          |  <p>Replace <code>YOUR_CLIENT_ID</code> and <code>YOUR_REDIRECT_URI</code>:</p>
          |  <pre>/auth?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&scope=openid%20profile%20email&state=abc123</pre>
          |</body>
          |</html>
        """.stripMargin).map(_.withContentType(org.http4s.headers.`Content-Type`(MediaType.text.html)))
    }
  }
}