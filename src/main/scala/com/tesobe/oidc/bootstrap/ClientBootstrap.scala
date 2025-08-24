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
import com.tesobe.oidc.auth.{DatabaseAuthService, AdminDatabaseClient}
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.OidcClient
import org.slf4j.LoggerFactory

import java.security.SecureRandom
import java.util.Base64
import scala.concurrent.duration._

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
    println("🎬 DEBUG: ClientBootstrap.initializeClients() called")
    logger.info("🎬 ClientBootstrap.initializeClients() called")
    // Check if client bootstrap is disabled
    val skipBootstrap = sys.env.get("OIDC_SKIP_CLIENT_BOOTSTRAP").exists(_.toLowerCase == "true")
    println(s"🔧 DEBUG: OIDC_SKIP_CLIENT_BOOTSTRAP = ${sys.env.get("OIDC_SKIP_CLIENT_BOOTSTRAP").getOrElse("not set")}")
    logger.info(s"🔧 OIDC_SKIP_CLIENT_BOOTSTRAP = ${sys.env.get("OIDC_SKIP_CLIENT_BOOTSTRAP").getOrElse("not set")}")
    
    if (skipBootstrap) {
      println("⏭️  DEBUG: Client bootstrap disabled via OIDC_SKIP_CLIENT_BOOTSTRAP environment variable")
      logger.info("⏭️  Client bootstrap disabled via OIDC_SKIP_CLIENT_BOOTSTRAP environment variable")
      IO.unit
    } else {
      println("🚦 DEBUG: Bootstrap not disabled - proceeding with client initialization")
      println("🚀 DEBUG: Initializing OBP ecosystem OIDC clients...")
      logger.info("🚦 Bootstrap not disabled - proceeding with client initialization")
      logger.info("🚀 Initializing OBP ecosystem OIDC clients...")
      logger.info("🔍 Step 1: Checking admin database availability...")
      
      // Check if admin database is available first
      println("🔍 DEBUG: About to check admin database availability...")
      checkAdminDatabaseAvailability().flatMap { adminAvailable =>
      println(s"📊 DEBUG: Admin database available = $adminAvailable")
      if (adminAvailable) {
        println("✅ DEBUG: Admin database available - proceeding with client management")
        logger.info("✅ Step 2: Admin database available - proceeding with client management")
        logger.info("🔧 Step 3: Creating/updating OBP ecosystem clients...")
        for {
          _ <- IO(println("🔧 DEBUG: Starting individual client creation..."))
          _ <- ensureClient(createOBPAPIClient())
          _ <- IO(println("🔧 DEBUG: OBP-API client processing completed"))
          _ <- ensureClient(createPortalClient())
          _ <- IO(println("🔧 DEBUG: Portal client processing completed"))
          _ <- ensureClient(createExplorerIIClient())
          _ <- IO(println("🔧 DEBUG: Explorer II client processing completed"))
          _ <- ensureClient(createOpeyIIClient())
          _ <- IO(println("🔧 DEBUG: Opey II client processing completed"))
          _ <- logClientConfiguration()
        } yield {
          println("✅ DEBUG: All OBP ecosystem clients initialized successfully")
          logger.info("✅ All OBP ecosystem clients initialized successfully")
        }
      } else {
      println("❌ DEBUG: Admin database not available - skipping automatic client creation")
      logger.warn("❌ Step 2: Admin database not available - skipping automatic client creation")
      logger.info("📋 Step 3: Generating manual SQL commands instead...")
      logManualClientCreationSQL()
    }
      }
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
   * Check if admin database is available for client operations
   */
  private def checkAdminDatabaseAvailability(): IO[Boolean] = {
    println("   🔍 DEBUG: Testing admin database with listClients() operation...")
    logger.info("   🔍 Testing admin database with listClients() operation...")
    // Try a simple admin database operation with timeout
    IO.race(
      IO.sleep(5.seconds),
      authService.listClients()
    ).map {
      case Left(_) => 
        println("   ⏱️ DEBUG: Admin database check TIMED OUT after 5 seconds")
        logger.warn("   ⏱️ Admin database check timed out after 5 seconds")
        false
      case Right(result) => 
        result match {
          case Right(clients) =>
            println(s"   ✅ DEBUG: Admin database responds - found ${clients.length} existing clients")
            logger.info(s"   ✅ Admin database responds - found ${clients.length} existing clients")
            true
          case Left(error) =>
            println(s"   ❌ DEBUG: Admin database error: ${error.error} - ${error.error_description.getOrElse("No description")}")
            logger.warn(s"   ❌ Admin database error: ${error.error} - ${error.error_description.getOrElse("No description")}")
            false
        }
    }.handleErrorWith { error =>
      println(s"   ❌ DEBUG: Admin database exception: ${error.getClass.getSimpleName}: ${error.getMessage}")
      logger.warn(s"   ❌ Admin database exception: ${error.getMessage}")
      IO.pure(false)
    }
  }

  /**
   * Ensure client exists, create if not found, update if different
   */
  private def ensureClient(clientConfig: OidcClient): IO[Unit] = {
    // Add timeout to prevent hanging
    IO.race(
      IO.sleep(10.seconds),
      performClientOperation(clientConfig)
    ).flatMap {
      case Left(_) =>
        logger.error(s"⏱️ Client operation timed out for ${clientConfig.client_name}")
        IO.unit
      case Right(_) =>
        IO.unit
    }
  }

  private def performClientOperation(clientConfig: OidcClient): IO[Unit] = {
    println(s"   🔍 DEBUG: Checking if client exists: ${clientConfig.client_name} (${clientConfig.client_id})")
    logger.info(s"   🔍 Checking if client exists: ${clientConfig.client_name} (${clientConfig.client_id})")
    authService.findClientById(clientConfig.client_id).flatMap {
      case Some(existingClient) =>
        println(s"   ✅ DEBUG: Client exists: ${existingClient.client_name}")
        logger.info(s"   ✅ Client exists: ${existingClient.client_name}")
        if (needsUpdate(existingClient, clientConfig)) {
          println(s"   🔄 DEBUG: Client needs update: ${clientConfig.client_name} (${clientConfig.client_id})")
          logger.info(s"   🔄 Client needs update: ${clientConfig.client_name} (${clientConfig.client_id})")
          authService.updateClient(clientConfig.client_id, clientConfig).flatMap {
            case Right(_) =>
              println(s"   ✅ DEBUG: Successfully updated client: ${clientConfig.client_name}")
              logger.info(s"   ✅ Successfully updated client: ${clientConfig.client_name}")
              IO.unit
            case Left(error) =>
              println(s"   ❌ DEBUG: Failed to update client ${clientConfig.client_name}: ${error.error} - ${error.error_description.getOrElse("No description")}")
              logger.error(s"   ❌ Failed to update client ${clientConfig.client_name}: ${error.error} - ${error.error_description.getOrElse("No description")}")
              IO.unit
          }
        } else {
          println(s"   ✅ DEBUG: Client already up-to-date: ${clientConfig.client_name} (${clientConfig.client_id})")
          logger.info(s"   ✅ Client already up-to-date: ${clientConfig.client_name} (${clientConfig.client_id})")
          IO.unit
        }
      case None =>
        println(s"   ➕ DEBUG: Client not found - creating new client: ${clientConfig.client_name} (${clientConfig.client_id})")
        logger.info(s"   ➕ Client not found - creating new client: ${clientConfig.client_name} (${clientConfig.client_id})")
        authService.createClient(clientConfig).flatMap {
          case Right(_) =>
            println(s"   ✅ DEBUG: Successfully created client: ${clientConfig.client_name}")
            logger.info(s"   ✅ Successfully created client: ${clientConfig.client_name}")
            IO.unit
          case Left(error) =>
            println(s"   ❌ DEBUG: Failed to create client ${clientConfig.client_name}: ${error.error} - ${error.error_description.getOrElse("No description")}")
            logger.error(s"   ❌ Failed to create client ${clientConfig.client_name}: ${error.error} - ${error.error_description.getOrElse("No description")}")
            logger.error(s"   💡 Hint: Check if admin user has write permissions to v_oidc_admin_clients")
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
   * Log manual client creation SQL when admin database is not available
   */
  private def logManualClientCreationSQL(): IO[Unit] = {
    val clients = List(
      createOBPAPIClient(),
      createPortalClient(),
      createExplorerIIClient(), 
      createOpeyIIClient()
    )

    IO {
      logger.info("📋 Manual Client Creation SQL:")
      logger.info("=" * 60)
      
      clients.foreach { client =>
        logger.info(s"""
INSERT INTO v_oidc_admin_clients (
  name, apptype, description, developeremail, sub,
  secret, azp, aud, iss, redirecturl, company, key_c, isactive
) VALUES (
  '${client.client_name}',
  'WEB',
  'OIDC client for ${client.client_name}',
  'admin@tesobe.com',
  '${client.client_id}',
  '${client.client_secret.getOrElse("GENERATE_SECURE_SECRET")}',
  '${client.client_id}',
  'obp-api',
  'obp-oidc',
  '${client.redirect_uris.mkString(",")}',
  'TESOBE',
  '${client.client_id}',
  true
);""")
      }
      
      logger.info("=" * 60)
      logger.info("💡 Run these SQL commands manually to create OIDC clients")
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
  
  private val logger = LoggerFactory.getLogger(getClass)
  
  /**
   * Create and run client bootstrap
   */
  def initialize(authService: DatabaseAuthService, config: OidcConfig): IO[Unit] = {
    println("🎯 DEBUG: ClientBootstrap.initialize() called from server")
    logger.info("🎯 ClientBootstrap.initialize() called from server")
    new ClientBootstrap(authService, config).initializeClients()
  }
}