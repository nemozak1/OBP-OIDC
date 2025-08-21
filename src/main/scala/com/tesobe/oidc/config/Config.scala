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

package com.tesobe.oidc.config

import cats.effect.IO

case class ServerConfig(
  host: String,
  port: Int
)

case class DatabaseConfig(
  host: String,
  port: Int,
  database: String,
  username: String,
  password: String,
  maxConnections: Int = 10
)

case class OidcConfig(
  issuer: String,
  server: ServerConfig,
  database: DatabaseConfig,
  keyId: String = "oidc-key-1",
  tokenExpirationSeconds: Long = 3600, // 1 hour
  codeExpirationSeconds: Long = 600     // 10 minutes
)

object Config {
  
  def load: IO[OidcConfig] = IO {
    val host = sys.env.getOrElse("OIDC_HOST", "localhost")
    val port = sys.env.getOrElse("OIDC_PORT", "9000").toInt
    val issuer = sys.env.getOrElse("OIDC_ISSUER", s"http://$host:$port")
    
    val dbConfig = DatabaseConfig(
      host = sys.env.getOrElse("DB_HOST", "localhost"),
      port = sys.env.getOrElse("DB_PORT", "5432").toInt,
      database = sys.env.getOrElse("DB_NAME", "sandbox"),
      username = sys.env.getOrElse("DB_USERNAME", "oidc_user"),
      password = sys.env.getOrElse("DB_PASSWORD", "CHANGE_THIS_TO_A_VERY_STRONG_PASSWORD_2024!"),
      maxConnections = sys.env.getOrElse("DB_MAX_CONNECTIONS", "10").toInt
    )
    
    OidcConfig(
      issuer = issuer,
      server = ServerConfig(host, port),
      database = dbConfig,
      keyId = sys.env.getOrElse("OIDC_KEY_ID", "oidc-key-1"),
      tokenExpirationSeconds = sys.env.getOrElse("OIDC_TOKEN_EXPIRATION", "3600").toLong,
      codeExpirationSeconds = sys.env.getOrElse("OIDC_CODE_EXPIRATION", "600").toLong
    )
  }
}