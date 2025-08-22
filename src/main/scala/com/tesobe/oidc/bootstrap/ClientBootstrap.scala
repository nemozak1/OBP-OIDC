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

package com.tesobe.oidc.bootstrap

import cats.effect.IO
import cats.implicits._
import com.tesobe.oidc.auth.DatabaseAuthService
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.OidcClient
import org.slf4j.LoggerFactory

import java.security.SecureRandom
import java.util.Base64

/**
 * Client Bootstrap Service
 * 
 * Automatically creates or updates standard OBP ecosystem clients on startup:
 * - OBP-API: Core banking API service
 * - Portal: OBP Portal web application
 * - Explorer II: API exploration tool
 * - Opey II: OBP mobile/web client
 */
class ClientBootstrap(authService: DatabaseAuthService, config: OidcConfig) {
  
  private val logger = LoggerFactory.getLogger(getClass)
  private val secureRandom = new SecureRandom()

  /**
   * Initialize all standard OBP clients
   */
  def initializeClients(): IO[Unit] = {
    logger.info("🚀 Initializing OBP ecosystem OIDC clients...")
    
    for {
      _ <- ensureClient(createOBPAPIClient())
      _ <- ensureClient(createPortalClient())
      _ <- ensureClient(createExplorerIIClient())
      _ <- ensureClient(createOpeyIIClient())
      _ <- logClientConfiguration()
    } yield {
      logger.info("✅ All OBP ecosystem clients initialized successfully")
    }
  }

  /**
   * Create OBP-API client configuration
   */
  private def createOBPAPIClient(): OidcClient = {
    val clientId = sys.env.getOrElse("OIDC_CLIENT_OBP_API_ID", "obp-api-client")
    val clientSecret = sys.env.getOrElse("OIDC_CLIENT_OBP_API_SECRET", generateSecureSecret())
    val redirectUris = sys.env.getOrElse("OIDC_CLIENT_OBP_API_REDIRECTS", "http://localhost:8080/oauth/callback").split(",").toList
    
    OidcClient(
      client_id = clientId,
      client_secret = Some(clientSecret),
      client_name = "OBP-API Core Service",
      redirect_uris = redirectUris,
      grant_types = List("authorization_code", "refresh_token"),
      response_types = List("code"),
      scopes = List("openid", "profile", "email"),
      token_endpoint_auth_method = "client_secret_basic",
      created_at = None
    )
  }

  /**
   * Create Portal client configuration
   */
  private def createPortalClient(): OidcClient = {
    val clientId = sys.env.getOrElse("OIDC_CLIENT_PORTAL_ID", "obp-portal-client")
    val clientSecret = sys.env.getOrElse("OIDC_CLIENT_PORTAL_SECRET", generateSecureSecret())
    val redirectUris = sys.env.getOrElse("OIDC_CLIENT_PORTAL_REDIRECTS", "http://localhost:3000/callback,http://localhost:3000/oauth/callback").split(",").toList
    
    OidcClient(
      client_id = clientId,
      client_secret = Some(clientSecret),
      client_name = "OBP Portal Web Application",
      redirect_uris = redirectUris,
      grant_types = List("authorization_code", "refresh_token"),
      response_types = List("code"),
      scopes = List("openid", "profile", "email"),
      token_endpoint_auth_method = "client_secret_basic",
      created_at = None
    )
  }

  /**
   * Create Explorer II client configuration
   */
  private def createExplorerIIClient(): OidcClient = {
    val clientId = sys.env.getOrElse("OIDC_CLIENT_EXPLORER_ID", "obp-explorer-ii-client")
    val clientSecret = sys.env.getOrElse("OIDC_CLIENT_EXPLORER_SECRET", generateSecureSecret())
    val redirectUris = sys.env.getOrElse("OIDC_CLIENT_EXPLORER_REDIRECTS", "http://localhost:3001/callback,http://localhost:3001/oauth/callback").split(",").toList
    
    OidcClient(
      client_id = clientId,
      client_secret = Some(clientSecret),
      client_name = "OBP Explorer II API Tool",
      redirect_uris = redirectUris,
      grant_types = List("authorization_code", "refresh_token"),
      response_types = List("code"),
      scopes = List("openid", "profile", "email"),
      token_endpoint_auth_method = "client_secret_basic",
      created_at = None
    )
  }

  /**
   * Create Opey II client configuration
   */
  private def createOpeyIIClient(): OidcClient = {
    val clientId = sys.env.getOrElse("OIDC_CLIENT_OPEY_ID", "obp-opey-ii-client")
    val clientSecret = sys.env.getOrElse("OIDC_CLIENT_OPEY_SECRET", generateSecureSecret())
    val redirectUris = sys.env.getOrElse("OIDC_CLIENT_OPEY_REDIRECTS", "http://localhost:3002/callback,http://localhost:3002/oauth/callback").split(",").toList
    
    OidcClient(
      client_id = clientId,
      client_secret = Some(clientSecret),
      client_name = "Opey II Mobile/Web Client",
      redirect_uris = redirectUris,
      grant_types = List("authorization_code", "refresh_token"),
      response_types = List("code"),
      scopes = List("openid", "profile", "email"),
      token_endpoint_auth_method = "client_secret_basic",
      created_at = None
    )
  }

  /**
   * Ensure client exists, create if not found, update if different
   */
  private def ensureClient(clientConfig: OidcClient): IO[Unit] = {
    authService.findClientById(clientConfig.client_id).flatMap {
      case Some(existingClient) =>
        if (needsUpdate(existingClient, clientConfig)) {
          logger.info(s"📝 Updating client: ${clientConfig.client_name} (${clientConfig.client_id})")
          authService.updateClient(clientConfig.client_id, clientConfig).flatMap {
            case Right(_) =>
              logger.info(s"✅ Successfully updated client: ${clientConfig.client_name}")
              IO.unit
            case Left(error) =>
              logger.error(s"❌ Failed to update client ${clientConfig.client_name}: ${error.error_description.getOrElse(error.error)}")
              IO.unit
          }
        } else {
          logger.info(s"✅ Client already exists and up-to-date: ${clientConfig.client_name} (${clientConfig.client_id})")
          IO.unit
        }
      case None =>
        logger.info(s"📝 Creating new client: ${clientConfig.client_name} (${clientConfig.client_id})")
        authService.createClient(clientConfig).flatMap {
          case Right(_) =>
            logger.info(s"✅ Successfully created client: ${clientConfig.client_name}")
            IO.unit
          case Left(error) =>
            logger.error(s"❌ Failed to create client ${clientConfig.client_name}: ${error.error_description.getOrElse(error.error)}")
            IO.unit
        }
    }
  }

  /**
   * Check if client needs updating
   */
  private def needsUpdate(existing: OidcClient, desired: OidcClient): Boolean = {
    existing.client_name != desired.client_name ||
    existing.redirect_uris.toSet != desired.redirect_uris.toSet ||
    existing.grant_types.toSet != desired.grant_types.toSet ||
    existing.response_types.toSet != desired.response_types.toSet ||
    existing.scopes.toSet != desired.scopes.toSet ||
    existing.token_endpoint_auth_method != desired.token_endpoint_auth_method ||
    (desired.client_secret.isDefined && existing.client_secret != desired.client_secret)
  }

  /**
   * Log configuration for all clients
   */
  private def logClientConfiguration(): IO[Unit] = {
    val clients = List(
      createOBPAPIClient(),
      createPortalClient(), 
      createExplorerIIClient(),
      createOpeyIIClient()
    )

    IO {
      logger.info("📋 OIDC Client Configuration Summary:")
      logger.info("=" * 60)
      
      clients.foreach { client =>
        logger.info(s"""
Client: ${client.client_name}
  ID: ${client.client_id}
  Secret: ${client.client_secret.getOrElse("NOT_SET")}
  Redirect URIs: ${client.redirect_uris.mkString(", ")}
  Grant Types: ${client.grant_types.mkString(", ")}
  Scopes: ${client.scopes.mkString(", ")}
  Auth Method: ${client.token_endpoint_auth_method}
""")
      }
      
      logger.info("=" * 60)
      logger.info("💡 Use these configurations in your service Props/environment files")
    }
  }

  /**
   * Generate a secure client secret
   */
  private def generateSecureSecret(): String = {
    val bytes = new Array[Byte](32) // 256 bits
    secureRandom.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
  }
}

object ClientBootstrap {
  
  /**
   * Create and run client bootstrap
   */
  def initialize(authService: DatabaseAuthService, config: OidcConfig): IO[Unit] = {
    new ClientBootstrap(authService, config).initializeClients()
  }
}