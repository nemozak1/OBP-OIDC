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

import scala.language.higherKinds
import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all._
import com.comcast.ip4s.{Host, Port}
import com.tesobe.oidc.auth.{CodeService, DatabaseAuthService, DatabaseClient}
import com.tesobe.oidc.models.OidcClient
import com.tesobe.oidc.bootstrap.ClientBootstrap
import com.tesobe.oidc.config.Config
import com.tesobe.oidc.endpoints._
import com.tesobe.oidc.tokens.JwtService
import org.http4s._
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._
import org.http4s.server.Router

import scala.concurrent.duration._

object OidcServer extends IOApp {

  def run(args: List[String]): IO[ExitCode] = {
    // Check for developer helper commands
    args.headOption match {
      case Some("--generate-config") | Some("--config") =>
        generateDeveloperConfig()
      case Some("--generate-db-config") | Some("--db-config") =>
        generateDatabaseConfig()
      case Some("--help") | Some("-h") =>
        printHelp()
      case _ =>
        startServer(args)
    }
  }

  private def startServer(args: List[String]): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(
        println(
          s"Starting OIDC Provider on ${config.server.host}:${config.server.port}"
        )
      )
      _ <- IO(println(s"Issuer: ${config.issuer}"))

      // Test database connections
      _ <- DatabaseAuthService.testConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) =>
          IO.raiseError(
            new RuntimeException(s"User database connection failed: $error")
          )
      }

      _ <- DatabaseAuthService.testClientConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) =>
          IO(
            println(s"Client database warning: $error (using permissive mode)")
          )
      }

      _ <- DatabaseAuthService.testAdminConnection(config).flatMap {
        case Right(msg) => IO(println(msg))
        case Left(error) =>
          IO(
            println(
              s"Admin database warning: $error (client management features disabled)"
            )
          )
      }

      exitCode <- DatabaseAuthService.create(config).use { authService =>
        for {
          // Initialize standard OBP ecosystem clients (create-only mode)
          _ <- IO(
            println(
              "🔧 DEBUG: Starting ClientBootstrap initialization (create-only mode)..."
            )
          )
          _ <- IO(println("🔧 Starting ClientBootstrap initialization..."))
          _ <- IO
            .race(
              IO.sleep(15.seconds),
              ClientBootstrap.initialize(authService, config)
            )
            .flatMap {
              case Left(_) =>
                IO(
                  println(
                    "⚠️ DEBUG: Client initialization TIMED OUT after 15 seconds"
                  )
                )
                IO(
                  println(
                    "⚠️ Client initialization timed out after 15 seconds - continuing server startup"
                  )
                )
              case Right(_) =>
                IO(
                  println(
                    "✅ DEBUG: Client initialization completed successfully"
                  )
                )
                IO(println("✅ Client initialization completed successfully"))
            }
            .handleErrorWith { error =>
              IO(
                println(
                  s"❌ DEBUG: Client initialization FAILED with error: ${error.getClass.getSimpleName}: ${error.getMessage}"
                )
              )
              IO(
                println(
                  s"⚠️ Client initialization failed: ${error.getMessage} - continuing server startup"
                )
              )
              IO(error.printStackTrace())
            }

          // Initialize services
          codeService <- CodeService(config)
          jwtService <- JwtService(config)

          // Initialize endpoints
          discoveryEndpoint = DiscoveryEndpoint(config)
          jwksEndpoint = JwksEndpoint(jwtService)
          authEndpoint = AuthEndpoint(authService, codeService)
          tokenEndpoint = TokenEndpoint(
            authService,
            codeService,
            jwtService,
            config
          )
          userInfoEndpoint = UserInfoEndpoint(authService, jwtService)

          // Create all routes in a single HttpRoutes definition
          routes = {
            import org.http4s.dsl.io._

            HttpRoutes
              .of[IO] {
                // Health check
                case GET -> Root / "health" =>
                  IO(println("🏥 Health check requested")) *>
                    Ok("OIDC Provider is running")

                // Root page
                case GET -> Root =>
                  Ok(s"""<!DOCTYPE html>
                     |<html>
                     |<head><title>OBP OIDC Provider</title></head>
                     |<body>
                     |<h1>OBP OIDC Provider</h1>
                     |<p>OpenID Connect provider is running</p>
                     |<p><strong>Version:</strong> v2.0.0-DEBUG-${java.time.Instant
                         .now()}</p>
                     |<p><em>🐛 Debug mode enabled - Enhanced logging for azp claim troubleshooting</em></p>
                     |<h2>Endpoints:</h2>
                     |<ul>
                     |<li><a href="/obp-oidc/.well-known/openid-configuration">Discovery</a></li>
                     |<li><a href="/obp-oidc/jwks">JWKS</a></li>
                     |<li><a href="/health">Health Check</a></li>
                     |</ul>
                     |</body>
                     |</html>""".stripMargin)
                    .map(
                      _.withContentType(
                        org.http4s.headers.`Content-Type`(MediaType.text.html)
                      )
                    )

                // OIDC Discovery
                case GET -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
                  discoveryEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.GET,
                        org.http4s.Uri.unsafeFromString(
                          "/obp-oidc/.well-known/openid-configuration"
                        )
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None => NotFound("Discovery endpoint not found")
                    }

                // JWKS
                case GET -> Root / "obp-oidc" / "jwks" =>
                  jwksEndpoint.routes
                    .run(
                      org.http4s.Request[IO](
                        org.http4s.Method.GET,
                        org.http4s.Uri.unsafeFromString("/obp-oidc/jwks")
                      )
                    )
                    .value
                    .flatMap {
                      case Some(resp) => IO.pure(resp)
                      case None       => NotFound("JWKS endpoint not found")
                    }

                // Delegate other requests to endpoints
                case req =>
                  IO(
                    println(
                      s"🌐 Incoming request: ${req.method} ${req.uri} - Content-Type: ${req.headers.get[headers.`Content-Type`].map(_.mediaType).getOrElse("MISSING")}"
                    )
                  ) *>
                    authEndpoint.routes.run(req).value.flatMap {
                      case Some(resp) =>
                        IO(println(s"🔐 Request handled by AuthEndpoint")) *>
                          IO.pure(resp)
                      case None =>
                        IO(
                          println(
                            s"🔐 AuthEndpoint did not handle request, trying TokenEndpoint"
                          )
                        ) *>
                          tokenEndpoint.routes.run(req).value.flatMap {
                            case Some(resp) =>
                              IO(
                                println(s"🎫 Request handled by TokenEndpoint")
                              ) *>
                                IO.pure(resp)
                            case None =>
                              IO(
                                println(
                                  s"🎫 TokenEndpoint did not handle request, trying UserInfoEndpoint"
                                )
                              ) *>
                                userInfoEndpoint.routes.run(req).value.flatMap {
                                  case Some(resp) =>
                                    IO(
                                      println(
                                        s"👤 Request handled by UserInfoEndpoint"
                                      )
                                    ) *>
                                      IO.pure(resp)
                                  case None =>
                                    IO(
                                      println(
                                        s"❌ No endpoint handled the request: ${req.method} ${req.uri}"
                                      )
                                    ) *>
                                      NotFound("Endpoint not found")
                                }
                          }
                    }
              }
              .orNotFound
          }

          // Start server
          host <- IO.fromOption(Host.fromString(config.server.host))(
            new RuntimeException(s"Invalid host: ${config.server.host}")
          )
          port <- IO.fromOption(Port.fromInt(config.server.port))(
            new RuntimeException(s"Invalid port: ${config.server.port}")
          )

          _ <- EmberServerBuilder
            .default[IO]
            .withHost(host)
            .withPort(port)
            .withHttpApp(routes)
            .build
            .use { server =>
              val baseUriString = server.baseUri.toString.stripSuffix("/")
              IO(println(s"OIDC Provider started at ${server.baseUri}")) *>
                IO(println("Available endpoints:")) *>
                IO(
                  println(
                    s"  Discovery: $baseUriString/.well-known/openid-configuration"
                  )
                ) *>
                IO(println(s"  Authorization: $baseUriString/auth")) *>
                IO(println(s"  Token: $baseUriString/token")) *>
                IO(println(s"  UserInfo: $baseUriString/userinfo")) *>
                IO(println(s"  JWKS: $baseUriString/jwks")) *>
                IO(println(s"  Health Check: $baseUriString/health")) *>
                printOBPConfiguration(baseUriString, authService) *>
                IO.never
            }
        } yield ExitCode.Success
      }
    } yield exitCode
  }.handleErrorWith { error =>
    IO(println(s"Failed to start OIDC Provider: ${error.getMessage}")) >>
      IO(error.printStackTrace()) >>
      IO.pure(ExitCode.Error)
  }

  /** Generate developer configuration (database + OIDC clients)
    */
  private def generateDeveloperConfig(): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- IO(println("🚀 OBP-OIDC Developer Configuration Generator"))
      _ <- IO(println())
      _ <- ClientBootstrap.generateDatabaseConfig(config)
      _ <- IO(
        println(
          "📋 Next, run the database setup commands above, then start OBP-OIDC to generate OIDC client configurations."
        )
      )
      _ <- IO(
        println(
          "💡 Or run: ./mvn exec:java to start the server and auto-generate everything."
        )
      )
    } yield ExitCode.Success
  }

  /** Generate only database configuration
    */
  private def generateDatabaseConfig(): IO[ExitCode] = {
    for {
      config <- Config.load
      _ <- ClientBootstrap.generateDatabaseConfig(config)
    } yield ExitCode.Success
  }

  /** Print help information
    */
  private def printHelp(): IO[ExitCode] = {
    IO {
      println()
      println("🚀 OBP-OIDC Developer Helper")
      println("=" * 50)
      println()
      println("Usage:")
      println("  java -jar target/obp-oidc-1.0.0-SNAPSHOT.jar [COMMAND]")
      println()
      println("Commands:")
      println(
        "  --generate-config    Generate database + OIDC client configuration"
      )
      println("  --db-config         Generate only database configuration")
      println("  --help, -h          Show this help")
      println()
      println("Default (no command): Start OIDC server")
      println()
      println("Examples:")
      println("  # Generate all developer configuration")
      println("  java -jar obp-oidc.jar --generate-config")
      println()
      println("  # Start server (auto-generates client configs)")
      println("  java -jar obp-oidc.jar")
      println()
    } *> IO.pure(ExitCode.Success)
  }

  /** Print configuration for all OBP projects using existing ClientBootstrap
    * clients
    */
  private def printOBPConfiguration(
      baseUri: String,
      authService: DatabaseAuthService
  ): IO[Unit] = {
    // Get client configurations from the bootstrap system
    val obpApiClientId =
      sys.env.getOrElse("OIDC_CLIENT_OBP_API_ID", "obp-api-client")
    val portalClientId =
      sys.env.getOrElse("OIDC_CLIENT_PORTAL_ID", "obp-portal-client")
    val explorerClientId =
      sys.env.getOrElse("OIDC_CLIENT_EXPLORER_ID", "obp-explorer-ii-client")
    val opeyClientId =
      sys.env.getOrElse("OIDC_CLIENT_OPEY_ID", "obp-opey-ii-client")

    for {
      _ <- IO(println(s"🔍 DEBUG: Looking for clients with IDs:"))
      _ <- IO(println(s"   OBP-API: $obpApiClientId"))
      _ <- IO(println(s"   Portal: $portalClientId"))
      _ <- IO(println(s"   Explorer: $explorerClientId"))
      _ <- IO(println(s"   Opey: $opeyClientId"))

      // Fetch actual client configurations from database
      obpApiClient <- authService.findAdminClientById(obpApiClientId)
      portalClient <- authService.findAdminClientById(portalClientId)
      explorerClient <- authService.findAdminClientById(explorerClientId)
      opeyClient <- authService.findAdminClientById(opeyClientId)

      _ <- IO(println(s"🔍 DEBUG: Client lookup results:"))
      _ <- IO(
        println(
          s"   OBP-API: ${if (obpApiClient.isDefined) "FOUND" else "NOT FOUND"}"
        )
      )
      _ <- IO(
        println(
          s"   Portal: ${if (portalClient.isDefined) "FOUND" else "NOT FOUND"}"
        )
      )
      _ <- IO(println(s"   Explorer: ${if (explorerClient.isDefined) "FOUND"
        else "NOT FOUND"}"))
      _ <- IO(
        println(
          s"   Opey: ${if (opeyClient.isDefined) "FOUND" else "NOT FOUND"}"
        )
      )
      _ <- IO(println())

      _ <- IO(println())
      _ <- IO(println("=" * 100))
      _ <- IO(println("🚀 OBP PROJECT CONFIGURATIONS - Ready to copy & paste"))
      _ <- IO(println("=" * 100))
      _ <- IO(println())

      _ <- printOBPApiConfig(baseUri, obpApiClient)
      _ <- printPortalConfig(baseUri, portalClient)
      _ <- printApiExplorerConfig(baseUri, explorerClient)
      _ <- printOpeyConfig(baseUri, opeyClient)

      _ <- IO(println("=" * 100))
      _ <- IO(println("✅ All configurations printed above. Happy coding! 🎉"))
      _ <- IO(
        println(
          "💡 Note: Client secrets shown above are from your v_oidc_clients database"
        )
      )
      _ <- IO(println("=" * 100))
      _ <- IO(println())
    } yield ()
  }

  /** Print OBP-API configuration for props file
    */
  private def printOBPApiConfig(
      baseUri: String,
      client: Option[OidcClient]
  ): IO[Unit] = {
    val clientId = client.map(_.client_id).getOrElse("obp-api-client")
    val clientSecret =
      client.flatMap(_.client_secret).getOrElse("CLIENT_NOT_REGISTERED")
    println(s"🔑 DEBUG: OBP-API client id: ${clientId}")

    for {
      _ <- IO(println("📋 1. OBP-API Configuration (props file):"))
      _ <- IO(println("-" * 50))
      _ <- IO(println("# Add to your OBP-API props file"))
      _ <- IO(println("openid_connect.scope=openid email profile"))
      _ <- IO(println())
      _ <- IO(println("# OBP-API OIDC Provider Settings"))
      _ <- IO(println("openid_connect_1.button_text=OBP-OIDC"))
      _ <- IO(println(s"openid_connect_1.client_id=$clientId"))
      _ <- IO(println(s"openid_connect_1.client_secret=$clientSecret"))
      _ <- IO(
        println(
          s"openid_connect_1.callback_url=${sys.env.getOrElse("OBP_API_URL", "http://localhost:8080")}/auth/openid-connect/callback"
        )
      )
      _ <- IO(
        println(
          s"openid_connect_1.endpoint.discovery=$baseUri/obp-oidc/.well-known/openid-configuration"
        )
      )
      _ <- IO(
        println(
          s"openid_connect_1.endpoint.authorization=$baseUri/obp-oidc/auth"
        )
      )
      _ <- IO(
        println(
          s"openid_connect_1.endpoint.userinfo=$baseUri/obp-oidc/userinfo"
        )
      )
      _ <- IO(
        println(s"openid_connect_1.endpoint.token=$baseUri/obp-oidc/token")
      )
      _ <- IO(
        println(s"openid_connect_1.endpoint.jwks_uri=$baseUri/obp-oidc/jwks")
      )
      _ <- IO(println("openid_connect_1.access_type_offline=true"))
      _ <- IO(println())
      _ <-
        if (client.isEmpty) {
          IO(
            println(
              "⚠️  Client not found in database - check ClientBootstrap logs"
            )
          )
        } else IO.unit
    } yield ()
  }

  /** Print Portal configuration for .env file
    */
  private def printPortalConfig(
      baseUri: String,
      client: Option[OidcClient]
  ): IO[Unit] = {
    val clientId = client.map(_.client_id).getOrElse("obp-portal-client")
    val clientSecret =
      client.flatMap(_.client_secret).getOrElse("CLIENT_NOT_REGISTERED")
    println(s"🔑 DEBUG: Portal client id: $clientId")

    for {
      _ <- IO(println("🌐 2. OBP-Portal Configuration (.env file):"))
      _ <- IO(println("-" * 50))
      _ <- IO(println("# Add to OBP-Portal .env file"))
      _ <- IO(
        println(
          s"OBP_API_HOST=${sys.env.getOrElse("OBP_API_HOST", "localhost:8080")}"
        )
      )
      _ <- IO(
        println(
          s"OBP_API_URL=${sys.env.getOrElse("OBP_API_URL", "http://localhost:8080")}"
        )
      )
      _ <- IO(println(s"OBP_OAUTH_CLIENT_ID=$clientId"))
      _ <- IO(println(s"OBP_OAUTH_CLIENT_SECRET=$clientSecret"))
      _ <- IO(
        println(
          s"OBP_OAUTH_WELL_KNOWN_URL=$baseUri/obp-oidc/.well-known/openid-configuration"
        )
      )
      _ <- IO(
        println("APP_CALLBACK_URL=http://localhost:5174/login/obp/callback")
      )
      _ <- IO(
        println(
          s"VITE_API_URL=${sys.env.getOrElse("OBP_API_URL", "http://localhost:8080")}"
        )
      )
      _ <- IO(println(s"VITE_OIDC_ISSUER=$baseUri"))
      _ <- IO(println(s"VITE_CLIENT_ID=$clientId"))
      _ <- IO(println())
      _ <-
        if (client.isEmpty) {
          IO(
            println(
              "⚠️  Client not found in database - check ClientBootstrap logs"
            )
          )
        } else IO.unit
    } yield ()
  }

  /** Print API Explorer II configuration for .env file
    */
  private def printApiExplorerConfig(
      baseUri: String,
      client: Option[OidcClient]
  ): IO[Unit] = {
    val clientId = client.map(_.client_id).getOrElse("explorer-ii-client")
    val clientSecret =
      client.flatMap(_.client_secret).getOrElse("CLIENT_NOT_REGISTERED")
    println(s"🔑 DEBUG: Explorer client id: $clientId")

    for {
      _ <- IO(println("🔍 3. API-Explorer-II Configuration (.env file):"))
      _ <- IO(println("-" * 50))
      _ <- IO(println("# Add to API-Explorer-II .env file"))
      _ <- IO(
        println(
          s"REACT_APP_API_HOST=${sys.env.getOrElse("OBP_API_URL", "http://localhost:8080")}"
        )
      )
      _ <- IO(println(s"REACT_APP_OIDC_ISSUER=$baseUri"))
      _ <- IO(println(s"REACT_APP_OIDC_AUTH_URL=$baseUri/obp-oidc/auth"))
      _ <- IO(println(s"REACT_APP_OIDC_TOKEN_URL=$baseUri/obp-oidc/token"))
      _ <- IO(
        println(s"REACT_APP_OIDC_USERINFO_URL=$baseUri/obp-oidc/userinfo")
      )
      _ <- IO(println(s"REACT_APP_OIDC_CLIENT_ID=$clientId"))
      _ <- IO(println(s"REACT_APP_OIDC_CLIENT_SECRET=$clientSecret"))
      _ <- IO(
        println("REACT_APP_OIDC_REDIRECT_URI=http://localhost:3001/callback")
      )
      _ <- IO(println("REACT_APP_OIDC_SCOPE=openid profile email"))
      _ <- IO(println("PORT=3001"))
      _ <- IO(println("HTTPS=false"))
      _ <- IO(println())
      _ <-
        if (client.isEmpty) {
          IO(
            println(
              "⚠️  Client not found in database - check ClientBootstrap logs"
            )
          )
        } else IO.unit
    } yield ()
  }

  /** Print Opey II configuration for .env file
    */
  private def printOpeyConfig(
      baseUri: String,
      client: Option[OidcClient]
  ): IO[Unit] = {
    val clientId = client.map(_.client_id).getOrElse("opey-ii-client")
    val clientSecret =
      client.flatMap(_.client_secret).getOrElse("CLIENT_NOT_REGISTERED")
    println(s"🔑 DEBUG: Opey client id: $clientId")

    for {
      _ <- IO(println("🤖 4. Opey-II Configuration (.env file):"))
      _ <- IO(println("-" * 50))
      _ <- IO(println("# Add to Opey-II .env file"))
      _ <- IO(
        println(
          s"OBP_API_HOST=${sys.env.getOrElse("OBP_API_HOST", "localhost:8080")}"
        )
      )
      _ <- IO(
        println(
          s"NEXT_PUBLIC_API_URL=${sys.env.getOrElse("OBP_API_URL", "http://localhost:8080")}"
        )
      )
      _ <- IO(println(s"NEXT_PUBLIC_OIDC_ISSUER=$baseUri"))
      _ <- IO(println(s"OIDC_ISSUER=$baseUri"))
      _ <- IO(println(s"OIDC_AUTH_URL=$baseUri/obp-oidc/auth"))
      _ <- IO(println(s"OIDC_TOKEN_URL=$baseUri/obp-oidc/token"))
      _ <- IO(println(s"OIDC_USERINFO_URL=$baseUri/obp-oidc/userinfo"))
      _ <- IO(println(s"OIDC_CLIENT_ID=$clientId"))
      _ <- IO(println(s"OIDC_CLIENT_SECRET=$clientSecret"))
      _ <- IO(println(s"NEXT_PUBLIC_CLIENT_ID=$clientId"))
      _ <- IO(println("OIDC_REDIRECT_URI=http://localhost:8082/callback"))
      _ <- IO(println("NEXTAUTH_URL=http://localhost:8082"))
      _ <- IO(println("NEXTAUTH_SECRET=opey-nextauth-secret-key"))
      _ <- IO(println("OIDC_SCOPE=openid profile email"))
      _ <- IO(println("PORT=8082"))
      _ <- IO(println())
      _ <-
        if (client.isEmpty) {
          IO(
            println(
              "⚠️  Client not found in database - check ClientBootstrap logs"
            )
          )
        } else IO.unit
    } yield ()
  }

}
