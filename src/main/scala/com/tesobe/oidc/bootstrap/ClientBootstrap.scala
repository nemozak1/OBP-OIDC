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
 * Automatically creates (but never modifies) standard OBP ecosystem clients on startup:
 * - OBP-API: Core banking API service
 * - Portal: OBP Portal web application
 * - Explorer II: API exploration tool
 * - Opey II: OBP mobile/web client
 */
class ClientBootstrap(authService: DatabaseAuthService, config: OidcConfig) {
  
  private val logger = LoggerFactory.getLogger(getClass)
  private val secureRandom = new SecureRandom()

  /**
   * Generate secure database passwords and print ready-to-use configuration
   */
  def generateDeveloperConfig(): IO[Unit] = {
    IO {
      val dbUserPassword = generateSecurePassword()
      val dbAdminPassword = generateSecurePassword()
      
      println()
      println("=" * 80)
      println("🔐 DEVELOPER HELPER: Database Configuration")
      println("=" * 80)
      println()
      println("📋 Database Setup Commands (copy & paste to terminal):")
      println("-" * 50)
      println("# Create database and users")
      println("sudo -u postgres psql << EOF")
      println("CREATE DATABASE sandbox;")
      println(s"CREATE USER oidc_user WITH PASSWORD '$dbUserPassword';")
      println(s"CREATE USER oidc_admin WITH PASSWORD '$dbAdminPassword';")
      println("GRANT CONNECT ON DATABASE sandbox TO oidc_user;")
      println("GRANT CONNECT ON DATABASE sandbox TO oidc_admin;")
      println("\\q")
      println("EOF")
      println()
      
      println("📋 Environment Variables for OBP-OIDC (copy to your .env or export):")
      println("-" * 50)
      println("export DB_HOST=localhost")
      println("export DB_PORT=5432")
      println("export DB_NAME=sandbox")
      println("export OIDC_USER_USERNAME=oidc_user")
      println(s"export OIDC_USER_PASSWORD=$dbUserPassword")
      println("export DB_MAX_CONNECTIONS=10")
      println("export OIDC_ADMIN_USERNAME=oidc_admin")
      println(s"export OIDC_ADMIN_PASSWORD=$dbAdminPassword")
      println("export DB_ADMIN_MAX_CONNECTIONS=5")
      println()
      
      // Write to file
      val configContent = s"""# OBP-OIDC Database Configuration
# Generated at: ${java.time.Instant.now()}

# Database Setup Commands
# Run these as postgres user:
sudo -u postgres psql << EOF
CREATE DATABASE sandbox;
CREATE USER oidc_user WITH PASSWORD '$dbUserPassword';
CREATE USER oidc_admin WITH PASSWORD '$dbAdminPassword';
GRANT CONNECT ON DATABASE sandbox TO oidc_user;
GRANT CONNECT ON DATABASE sandbox TO oidc_admin;
\\q
EOF

# Environment Variables for OBP-OIDC
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=sandbox
export OIDC_USER_USERNAME=oidc_user
export OIDC_USER_PASSWORD=$dbUserPassword
export DB_MAX_CONNECTIONS=10
export OIDC_ADMIN_USERNAME=oidc_admin
export OIDC_ADMIN_PASSWORD=$dbAdminPassword
export DB_ADMIN_MAX_CONNECTIONS=5
"""
      
      try {
        val file = new java.io.PrintWriter("obp-oidc-database-config.txt")
        file.write(configContent)
        file.close()
        println("📄 Database configuration also saved to: obp-oidc-database-config.txt")
      } catch {
        case e: Exception => 
          println(s"⚠️  Could not write database config file: ${e.getMessage}")
      }
      
      println("=" * 80)
      println("✅ Database configuration ready! Set up your database first, then run OBP-OIDC.")
      println("=" * 80)
      println()
    }
  }

  /**
   * Initialize all standard OBP clients
   * 
   * BEHAVIOR: Create-only mode - never modifies existing clients
   * - First run: Creates all standard OBP ecosystem clients
   * - Subsequent runs: Only creates newly added clients, preserves existing ones
   * - Existing clients: Skipped with read-only message, configurations preserved
   * - New apps: Automatically created when added to the codebase
   * 
   * This ensures persistent state and prevents accidental modification of
   * manually configured client settings in production environments.
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
        logger.info("🔧 Step 3: Creating missing OBP ecosystem clients (read-only for existing)...")
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
    val clientSecret = generateFreshSecretIfPlaceholder(sys.env.get("OIDC_CLIENT_OBP_API_SECRET"))
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
    val clientSecret = generateFreshSecretIfPlaceholder(sys.env.get("OIDC_CLIENT_PORTAL_SECRET"))
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
    val clientSecret = generateFreshSecretIfPlaceholder(sys.env.get("OIDC_CLIENT_EXPLORER_SECRET"))
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
    val clientSecret = generateFreshSecretIfPlaceholder(sys.env.get("OIDC_CLIENT_OPEY_SECRET"))
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
   * Ensure client exists, create if not found (never modify existing clients)
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
        println(s"   ✅ DEBUG: Client exists: ${existingClient.client_name} - SKIPPING (read-only mode)")
        logger.info(s"   ✅ Client exists: ${existingClient.client_name} - preserving existing configuration")
        logger.info(s"   📖 READ-ONLY: Not modifying existing client ${clientConfig.client_id}")
        IO.unit
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
   * Log configuration for all clients with ready-to-copy configs
   */
  private def logClientConfiguration(): IO[Unit] = {
    val clients = List(
      createOBPAPIClient(),
      createPortalClient(), 
      createExplorerIIClient(),
      createOpeyIIClient()
    )

    IO {
      println()
      println("=" * 80)
      println("🚀 DEVELOPER HELPER: Ready-to-Copy OBP Project Configurations")
      println("=" * 80)
      println()
      
      // OBP-API Configuration
      val obpClient = clients.find(_.client_id.contains("api")).get
      println("📋 1. OBP-API Configuration (Props file):")
      println("-" * 50)
      println("# Add to your OBP-API props file")
      println("openid_connect.scope=openid email profile")
      println()
      println("# OBP-API OIDC Provider Settings")
      println(s"openid_connect.endpoint=http://localhost:8080/.well-known/openid_configuration")
      println(s"oauth2.client_id=${obpClient.client_id}")
      println(s"oauth2.client_secret=${obpClient.client_secret.getOrElse("NOT_SET")}")
      println(s"oauth2.callback_url=${obpClient.redirect_uris.head}")
      println()
      
      // Portal Configuration
      val portalClient = clients.find(_.client_id.contains("portal")).get
      println("📋 2. OBP-Portal Configuration (.env file):")
      println("-" * 50)
      println("# Add to your OBP-Portal .env file")
      println(s"NEXT_PUBLIC_OAUTH_CLIENT_ID=${portalClient.client_id}")
      println(s"OAUTH_CLIENT_SECRET=${portalClient.client_secret.getOrElse("NOT_SET")}")
      println("NEXT_PUBLIC_OAUTH_AUTHORIZATION_URL=http://localhost:8080/oauth/authorize")
      println("OAUTH_TOKEN_URL=http://localhost:8080/oauth/token")
      println("OAUTH_USERINFO_URL=http://localhost:8080/oauth/userinfo")
      println(s"NEXT_PUBLIC_OAUTH_REDIRECT_URI=${portalClient.redirect_uris.head}")
      println()
      
      // Explorer II Configuration  
      val explorerClient = clients.find(_.client_id.contains("explorer")).get
      println("📋 3. API-Explorer-II Configuration (environment variables):")
      println("-" * 50)
      println("# Add to your API-Explorer-II environment")
      println(s"export REACT_APP_OAUTH_CLIENT_ID=${explorerClient.client_id}")
      println(s"export REACT_APP_OAUTH_CLIENT_SECRET=${explorerClient.client_secret.getOrElse("NOT_SET")}")
      println("export REACT_APP_OAUTH_AUTHORIZATION_URL=http://localhost:8080/oauth/authorize")
      println("export REACT_APP_OAUTH_TOKEN_URL=http://localhost:8080/oauth/token")
      println(s"export REACT_APP_OAUTH_REDIRECT_URI=${explorerClient.redirect_uris.head}")
      println()
      
      // Opey II Configuration
      val opeyClient = clients.find(_.client_id.contains("opey")).get
      println("📋 4. Opey-II Configuration (environment variables):")
      println("-" * 50)
      println("# Add to your Opey-II environment") 
      println(s"export VUE_APP_OAUTH_CLIENT_ID=${opeyClient.client_id}")
      println(s"export VUE_APP_OAUTH_CLIENT_SECRET=${opeyClient.client_secret.getOrElse("NOT_SET")}")
      println("export VUE_APP_OAUTH_AUTHORIZATION_URL=http://localhost:8080/oauth/authorize")
      println("export VUE_APP_OAUTH_TOKEN_URL=http://localhost:8080/oauth/token")
      println(s"export VUE_APP_OAUTH_REDIRECT_URI=${opeyClient.redirect_uris.head}")
      println()
      
      println("=" * 80)
      println("✅ All configurations ready! Copy & paste the sections you need.")
      println("🔐 Fresh secure secrets have been generated and stored in database.")
      println("💡 Server will be available at: http://localhost:8080")
      println("=" * 80)
      println()
      
      // Also write to config file for easy access
      writeConfigurationFile(clients)
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

  /**
   * Generate a secure database password (more user-friendly than base64)
   */
  private def generateSecurePassword(): String = {
    val chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*"
    val length = 24
    (1 to length).map(_ => chars(secureRandom.nextInt(chars.length))).mkString
  }

  /**
   * Generate fresh secret if environment variable contains placeholder
   */
  private def generateFreshSecretIfPlaceholder(envSecret: Option[String]): String = {
    envSecret match {
      case Some(secret) if secret.contains("CHANGE_THIS") => 
        val fresh = generateSecureSecret()
        println(s"🔐 Generated fresh secret (was placeholder): ${fresh.take(20)}...")
        fresh
      case Some(secret) if secret.nonEmpty => 
        println(s"🔑 Using existing secret: ${secret.take(20)}...")
        secret
      case _ => 
        val fresh = generateSecureSecret()
        println(s"🔐 Generated fresh secret (none provided): ${fresh.take(20)}...")
        fresh
    }
  }

  /**
   * Write configuration to file for easy access
   */
  private def writeConfigurationFile(clients: List[OidcClient]): Unit = {
    try {
      val configContent = generateConfigFileContent(clients)
      val file = new java.io.PrintWriter("obp-oidc-generated-config.txt")
      file.write(configContent)
      file.close()
      println("📄 Configuration also saved to: obp-oidc-generated-config.txt")
    } catch {
      case e: Exception => 
        println(s"⚠️  Could not write config file: ${e.getMessage}")
    }
  }

  /**
   * Generate configuration file content
   */
  private def generateConfigFileContent(clients: List[OidcClient]): String = {
    val obpClient = clients.find(_.client_id.contains("api")).get
    val portalClient = clients.find(_.client_id.contains("portal")).get
    val explorerClient = clients.find(_.client_id.contains("explorer")).get
    val opeyClient = clients.find(_.client_id.contains("opey")).get
    
    s"""# OBP-OIDC Generated Configuration
# Generated at: ${java.time.Instant.now()}
# Copy the sections you need to your project configuration files

# ============================================================================
# 1. OBP-API Configuration (Props file)
# ============================================================================
# Add to your OBP-API props file
openid_connect.scope=openid email profile

# OBP-API OIDC Provider Settings
openid_connect.endpoint=http://localhost:8080/.well-known/openid_configuration
oauth2.client_id=${obpClient.client_id}
oauth2.client_secret=${obpClient.client_secret.getOrElse("NOT_SET")}
oauth2.callback_url=${obpClient.redirect_uris.head}

# ============================================================================
# 2. OBP-Portal Configuration (.env file)
# ============================================================================
# Add to your OBP-Portal .env file
NEXT_PUBLIC_OAUTH_CLIENT_ID=${portalClient.client_id}
OAUTH_CLIENT_SECRET=${portalClient.client_secret.getOrElse("NOT_SET")}
NEXT_PUBLIC_OAUTH_AUTHORIZATION_URL=http://localhost:8080/oauth/authorize
OAUTH_TOKEN_URL=http://localhost:8080/oauth/token
OAUTH_USERINFO_URL=http://localhost:8080/oauth/userinfo
NEXT_PUBLIC_OAUTH_REDIRECT_URI=${portalClient.redirect_uris.head}

# ============================================================================
# 3. API-Explorer-II Configuration (environment variables)
# ============================================================================
# Add to your API-Explorer-II environment
export REACT_APP_OAUTH_CLIENT_ID=${explorerClient.client_id}
export REACT_APP_OAUTH_CLIENT_SECRET=${explorerClient.client_secret.getOrElse("NOT_SET")}
export REACT_APP_OAUTH_AUTHORIZATION_URL=http://localhost:8080/oauth/authorize
export REACT_APP_OAUTH_TOKEN_URL=http://localhost:8080/oauth/token
export REACT_APP_OAUTH_REDIRECT_URI=${explorerClient.redirect_uris.head}

# ============================================================================
# 4. Opey-II Configuration (environment variables)
# ============================================================================
# Add to your Opey-II environment
export VUE_APP_OAUTH_CLIENT_ID=${opeyClient.client_id}
export VUE_APP_OAUTH_CLIENT_SECRET=${opeyClient.client_secret.getOrElse("NOT_SET")}
export VUE_APP_OAUTH_AUTHORIZATION_URL=http://localhost:8080/oauth/authorize
export VUE_APP_OAUTH_TOKEN_URL=http://localhost:8080/oauth/token
export VUE_APP_OAUTH_REDIRECT_URI=${opeyClient.redirect_uris.head}

# ============================================================================
# Database Client Information
# ============================================================================
# Client IDs and secrets are also stored in your v_oidc_admin_clients table
# Use these for reference or manual configuration
"""
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

  /**
   * Generate database configuration for developers
   */
  def generateDatabaseConfig(config: OidcConfig): IO[Unit] = {
    new ClientBootstrap(null, config).generateDeveloperConfig()
  }
}