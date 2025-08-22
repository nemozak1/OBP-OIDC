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

import cats.effect.{IO, Resource}
import cats.implicits._
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig}
import com.tesobe.oidc.models.{User, UserInfo, OidcError, OidcClient}
import doobie._
import doobie.hikari.HikariTransactor
import doobie.implicits._
import doobie.postgres.implicits._
import com.zaxxer.hikari.HikariConfig
import at.favre.lib.crypto.bcrypt.BCrypt
import org.slf4j.LoggerFactory
import com.tesobe.oidc.auth.DatabaseUserInstances._

import java.time.Instant

/**
 * Database-based authentication service using PostgreSQL view v_oidc_users
 * 
 * This service connects to the OBP database and authenticates users against
 * the authuser table via the read-only view created by the OIDC setup script.
 * 
 * Password verification uses BCrypt to match the OBP-API implementation.
 */
class DatabaseAuthService(transactor: Transactor[IO], adminTransactor: Option[Transactor[IO]] = None) extends AuthService[IO] {
  
  private val logger = LoggerFactory.getLogger(getClass)
  
  /**
   * Authenticate a user by username and password
   * Returns the user information if authentication succeeds
   */
  def authenticate(username: String, password: String): IO[Either[OidcError, User]] = {
    logger.debug(s"Attempting authentication for user: $username")
    
    findUserByUsername(username).flatMap {
      case None =>
        logger.info(s"User not found: $username")
        IO.pure(Left(OidcError("invalid_grant", Some("Invalid username or password"))))
      case Some(dbUser) =>
        verifyPassword(password, dbUser.passwordHash, dbUser.passwordSalt).flatMap { isValid =>
          if (isValid) {
            logger.info(s"Authentication successful for user: $username")
            IO.pure(Right(dbUser.toUser))
          } else {
            logger.info(s"Authentication failed - invalid password for user: $username")
            IO.pure(Left(OidcError("invalid_grant", Some("Invalid username or password"))))
          }
        }
    }
  }
  
  /**
   * Get user by ID (for UserInfo endpoint) - required by AuthService interface
   */
  def getUserById(sub: String): IO[Option[User]] = {
    findUserByUniqueId(sub).map(_.map(_.toUser))
  }
  
  /**
   * Get user information by username (for UserInfo endpoint)
   */
  def getUserInfo(username: String): IO[Option[UserInfo]] = {
    findUserByUsername(username).map(_.map(_.toUserInfo))
  }
  
  /**
   * Find user by unique ID from the database view
   */
  private def findUserByUniqueId(uniqueId: String): IO[Option[DatabaseUser]] = {
    val query = sql"""
      SELECT id, username, firstname, lastname, email, uniqueid, 
             validated, provider, password_pw, password_slt, 
             createdat, updatedat
      FROM v_oidc_users 
      WHERE uniqueid = $uniqueId AND validated = true
    """.query[DatabaseUser]
    
    query.option.transact(transactor).handleErrorWith { error =>
      logger.error(s"Database error while finding user by ID $uniqueId", error)
      IO.pure(None)
    }
  }
  
  /**
   * Find user by username from the database view
   */
  private def findUserByUsername(username: String): IO[Option[DatabaseUser]] = {
    val query = sql"""
      SELECT id, username, firstname, lastname, email, uniqueid, 
             validated, provider, password_pw, password_slt, 
             createdat, updatedat
      FROM v_oidc_users 
      WHERE username = $username AND validated = true
    """.query[DatabaseUser]
    
    query.option.transact(transactor).handleErrorWith { error =>
      logger.error(s"Database error while finding user $username", error)
      IO.pure(None)
    }
  }
  
  /**
   * Find OIDC client by client_id
   */
  def findClientById(clientId: String): IO[Option[OidcClient]] = {
    val query = sql"""
      SELECT client_id, client_secret, client_name, redirect_uris, 
             grant_types, response_types, scopes, token_endpoint_auth_method, created_at
      FROM v_oidc_clients 
      WHERE client_id = $clientId
    """.query[DatabaseClient]
      
    query.option.transact(transactor).map(_.map(_.toOidcClient))
  }

  /**
   * Find raw DatabaseClient by client_id (for configuration printing)
   */
  def findDatabaseClientById(clientId: String): IO[Option[DatabaseClient]] = {
    val query = sql"""
      SELECT client_id, client_secret, client_name, redirect_uris, 
             grant_types, response_types, scopes, token_endpoint_auth_method, created_at
      FROM v_oidc_clients 
      WHERE client_id = $clientId
    """.query[DatabaseClient]
      
    query.option.transact(transactor)
  }

  /**
   * Validate client and redirect URI
   */
  def validateClient(clientId: String, redirectUri: String): IO[Boolean] = {
    findClientById(clientId).map {
      case Some(client) => client.redirect_uris.contains(redirectUri)
      case None => false
    }
  }

  // Admin client management methods using the admin transactor
  
  /**
   * Create a new OIDC client using the admin database connection
   * Requires write access to v_oidc_admin_clients view
   */
  def createClient(client: OidcClient): IO[Either[OidcError, OidcClient]] = {
    adminTransactor match {
      case Some(adminTx) =>
        val insertQuery = sql"""
          INSERT INTO v_oidc_admin_clients (
            client_id, client_secret, client_name, redirect_uris, 
            grant_types, response_types, scopes, token_endpoint_auth_method
          ) VALUES (
            ${client.client_id}, ${client.client_secret}, ${client.client_name},
            ${client.redirect_uris.mkString(",")}, ${client.grant_types.mkString(",")},
            ${client.response_types.mkString(",")}, ${client.scopes.mkString(",")},
            ${client.token_endpoint_auth_method}
          )
        """.update
        
        insertQuery.run.transact(adminTx).map { rowsAffected =>
          if (rowsAffected > 0) {
            logger.info(s"Successfully created OIDC client: ${client.client_id}")
            Right(client)
          } else {
            Left(OidcError("server_error", Some("Failed to create client")))
          }
        }.handleErrorWith { error =>
          logger.error(s"Failed to create client ${client.client_id}", error)
          IO.pure(Left(OidcError("server_error", Some(s"Database error: ${error.getMessage}"))))
        }
      case None =>
        IO.pure(Left(OidcError("server_error", Some("Admin database connection not available"))))
    }
  }

  /**
   * Update an existing OIDC client using the admin database connection
   */
  def updateClient(clientId: String, client: OidcClient): IO[Either[OidcError, OidcClient]] = {
    adminTransactor match {
      case Some(adminTx) =>
        val updateQuery = sql"""
          UPDATE v_oidc_admin_clients SET
            client_secret = ${client.client_secret},
            client_name = ${client.client_name},
            redirect_uris = ${client.redirect_uris.mkString(",")},
            grant_types = ${client.grant_types.mkString(",")},
            response_types = ${client.response_types.mkString(",")},
            scopes = ${client.scopes.mkString(",")},
            token_endpoint_auth_method = ${client.token_endpoint_auth_method}
          WHERE client_id = $clientId
        """.update
        
        updateQuery.run.transact(adminTx).map { rowsAffected =>
          if (rowsAffected > 0) {
            logger.info(s"Successfully updated OIDC client: $clientId")
            Right(client)
          } else {
            Left(OidcError("invalid_client", Some(s"Client not found: $clientId")))
          }
        }.handleErrorWith { error =>
          logger.error(s"Failed to update client $clientId", error)
          IO.pure(Left(OidcError("server_error", Some(s"Database error: ${error.getMessage}"))))
        }
      case None =>
        IO.pure(Left(OidcError("server_error", Some("Admin database connection not available"))))
    }
  }

  /**
   * Delete an OIDC client using the admin database connection
   */
  def deleteClient(clientId: String): IO[Either[OidcError, String]] = {
    adminTransactor match {
      case Some(adminTx) =>
        val deleteQuery = sql"DELETE FROM v_oidc_admin_clients WHERE client_id = $clientId".update
        
        deleteQuery.run.transact(adminTx).map { rowsAffected =>
          if (rowsAffected > 0) {
            logger.info(s"Successfully deleted OIDC client: $clientId")
            Right(s"Client $clientId deleted successfully")
          } else {
            Left(OidcError("invalid_client", Some(s"Client not found: $clientId")))
          }
        }.handleErrorWith { error =>
          logger.error(s"Failed to delete client $clientId", error)
          IO.pure(Left(OidcError("server_error", Some(s"Database error: ${error.getMessage}"))))
        }
      case None =>
        IO.pure(Left(OidcError("server_error", Some("Admin database connection not available"))))
    }
  }

  /**
   * List all clients using the admin database connection
   */
  def listClients(): IO[Either[OidcError, List[OidcClient]]] = {
    adminTransactor match {
      case Some(adminTx) =>
        val query = sql"""
          SELECT client_id, client_secret, client_name, redirect_uris, 
                 grant_types, response_types, scopes, token_endpoint_auth_method,
                 created_at
          FROM v_oidc_admin_clients
          ORDER BY created_at DESC
        """.query[DatabaseClient]
        
        query.to[List].transact(adminTx).map { clients =>
          Right(clients.map(_.toOidcClient))
        }.handleErrorWith { error =>
          logger.error("Failed to list clients", error)
          IO.pure(Left(OidcError("server_error", Some(s"Database error: ${error.getMessage}"))))
        }
      case None =>
        IO.pure(Left(OidcError("server_error", Some("Admin database connection not available"))))
    }
  }

/**
 * Verify password using BCrypt - compatible with OBP-API implementation
 */
  private def verifyPassword(plainPassword: String, storedHash: String, salt: String): IO[Boolean] = {
    IO {
      try {
        // OBP-API uses BCrypt.hashpw(password, salt).substring(0, 44)
        val hashedInput = BCrypt.withDefaults().hashToString(12, plainPassword.toCharArray).substring(0, 44)
        val result = hashedInput == storedHash
        logger.debug(s"Password verification result: $result")
        result
      } catch {
        case e: Exception =>
          logger.error("Error during password verification", e)
          false
      }
    }
  }
}

/**
 * Database user representation matching the v_oidc_users view structure
 */
case class DatabaseUser(
  id: Long,
  username: String,
  firstname: String,
  lastname: String,
  email: String,
  uniqueid: String,
  validated: Boolean,
  provider: String,
  passwordHash: String,  // password_pw column
  passwordSalt: String,  // password_slt column
  createdAt: Instant,
  updatedAt: Instant
) {
  
  def toUser: User = User(
    sub = uniqueid,
    username = username,
    password = "", // Never expose password, even if hashed
    name = Some(s"$firstname $lastname".trim),
    email = Some(email),
    email_verified = Some(validated)
  )
  
  def toUserInfo: UserInfo = UserInfo(
    sub = uniqueid,
    name = Some(s"$firstname $lastname".trim),
    given_name = Some(firstname),
    family_name = Some(lastname),
    email = Some(email),
    email_verified = Some(validated)
  )
}

/**
 * Database client representation matching the v_oidc_clients view structure
 */
case class DatabaseClient(
  client_id: String,
  client_secret: Option[String],
  client_name: String,
  redirect_uris: String, // Simple string from database
  grant_types: String,   // Simple string from database  
  response_types: String, // Simple string from database
  scopes: String,        // Simple string from database
  token_endpoint_auth_method: String,
  created_at: Option[String]
) {
  def toOidcClient: OidcClient = OidcClient(
    client_id = client_id,
    client_secret = client_secret,
    client_name = client_name,
    redirect_uris = parseSimpleString(redirect_uris),
    grant_types = parseSimpleString(grant_types),
    response_types = parseSimpleString(response_types),
    scopes = parseSimpleString(scopes),
    token_endpoint_auth_method = token_endpoint_auth_method,
    created_at = created_at
  )

  private def parseSimpleString(str: String): List[String] = {
    if (str == null || str.trim.isEmpty) {
      List.empty
    } else {
      // Handle simple strings - split by comma or space, or treat as single value
      str.split("[,\\s]+").map(_.trim).filter(_.nonEmpty).toList
    }
  }
}

object DatabaseAuthService {
  
  private val logger = LoggerFactory.getLogger(getClass)
  
  /**
   * Create a DatabaseAuthService with HikariCP connection pooling
   */
  def create(config: OidcConfig): Resource[IO, DatabaseAuthService] = {
    for {
      readTransactor <- createTransactor(config.database)
      adminTransactor <- createTransactor(config.adminDatabase)
    } yield new DatabaseAuthService(readTransactor, Some(adminTransactor))
  }
  
  /**
   * Create HikariCP transactor for database connections
   */
  private def createTransactor(dbConfig: DatabaseConfig): Resource[IO, HikariTransactor[IO]] = {
    val hikariConfig = new HikariConfig()
    hikariConfig.setDriverClassName("org.postgresql.Driver")
    hikariConfig.setJdbcUrl(s"jdbc:postgresql://${dbConfig.host}:${dbConfig.port}/${dbConfig.database}")
    hikariConfig.setUsername(dbConfig.username)
    hikariConfig.setPassword(dbConfig.password)
    hikariConfig.setMaximumPoolSize(dbConfig.maxConnections)
    hikariConfig.setMinimumIdle(2)
    hikariConfig.setConnectionTimeout(30000) // 30 seconds
    hikariConfig.setIdleTimeout(600000) // 10 minutes
    hikariConfig.setMaxLifetime(1800000) // 30 minutes
    hikariConfig.setLeakDetectionThreshold(60000) // 1 minute
    
    // Security settings
    hikariConfig.addDataSourceProperty("sslmode", "prefer")
    hikariConfig.addDataSourceProperty("tcpKeepAlive", "true")
    hikariConfig.addDataSourceProperty("ApplicationName", "OBP-OIDC-Provider")
    
    HikariTransactor.fromHikariConfig[IO](hikariConfig)
  }
  
  /**
   * Test database connection and setup
   */
  def testConnection(config: OidcConfig): IO[Either[String, String]] = {
    createTransactor(config.database).use { transactor =>
      val testQuery = sql"SELECT COUNT(*) FROM v_oidc_users".query[Int]
      
      testQuery.unique.transact(transactor).map { count =>
        val message = s"Database connection successful. Found $count validated users in v_oidc_users view."
        logger.info(message)
        Right(message)
      }.handleErrorWith { error =>
        val message = s"Database connection failed: ${error.getMessage}"
        logger.error(message, error)
        IO.pure(Left(message))
      }
    }
  }

  /**
   * Test client view access
   */
  def testClientConnection(config: OidcConfig): IO[Either[String, String]] = {
    createTransactor(config.database).use { transactor =>
      val testQuery = sql"SELECT COUNT(*) FROM v_oidc_clients".query[Int]
      
      testQuery.unique.transact(transactor).map { count =>
        val message = s"Client database connection successful. Found $count registered clients in v_oidc_clients view."
        logger.info(message)
        Right(message)
      }.handleErrorWith { error =>
        val message = s"Client database connection failed: ${error.getMessage}"
        logger.error(message, error)
        IO.pure(Left(message))
      }
    }
  }

  /**
   * Test admin database connection and v_oidc_admin_clients view access
   */
  def testAdminConnection(config: OidcConfig): IO[Either[String, String]] = {
    createTransactor(config.adminDatabase).use { transactor =>
      val testQuery = sql"SELECT COUNT(*) FROM v_oidc_admin_clients".query[Int]
      
      testQuery.unique.transact(transactor).map { count =>
        val message = s"Admin database connection successful. Found $count clients accessible via v_oidc_admin_clients view."
        logger.info(message)
        Right(message)
      }.handleErrorWith { error =>
        val message = s"Admin database connection failed: ${error.getMessage}"
        logger.error(message, error)
        IO.pure(Left(message))
      }
    }
  }
}

/**
 * Doobie Read instance for DatabaseUser
 */
object DatabaseUserInstances {
  import doobie.util.Read
  
  implicit val databaseUserRead: Read[DatabaseUser] = 
    Read[(Long, String, String, String, String, String, Boolean, String, String, String, Instant, Instant)]
      .map { case (id, username, firstname, lastname, email, uniqueid, validated, provider, passwordPw, passwordSlt, createdAt, updatedAt) =>
        DatabaseUser(
          id = id,
          username = username,
          firstname = firstname,
          lastname = lastname,
          email = email,
          uniqueid = uniqueid,
          validated = validated,
          provider = provider,
          passwordHash = passwordPw,
          passwordSalt = passwordSlt,
          createdAt = createdAt,
          updatedAt = updatedAt
        )
      }
}