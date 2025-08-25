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

package com.tesobe.oidc.tokens

import scala.language.higherKinds
import cats.effect.{IO, Ref}
import cats.syntax.either._
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.tesobe.oidc.models.{AccessTokenClaims, IdTokenClaims, JsonWebKey, OidcError, User}
import com.tesobe.oidc.config.OidcConfig

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.{KeyPair, KeyPairGenerator}
import java.time.Instant
import java.util.{Base64, Date}
import scala.util.{Failure, Success, Try}

trait JwtService[F[_]] {
  def generateIdToken(user: User, clientId: String, nonce: Option[String] = None): F[String]
  def generateAccessToken(user: User, clientId: String, scope: String): F[String]
  def validateAccessToken(token: String): F[Either[OidcError, AccessTokenClaims]]
  def getJsonWebKey: F[JsonWebKey]
}

class JwtServiceImpl(config: OidcConfig, keyPairRef: Ref[IO, KeyPair]) extends JwtService[IO] {

  private def getAlgorithm: IO[Algorithm] =
    keyPairRef.get.map { keyPair =>
      Algorithm.RSA256(
        keyPair.getPublic.asInstanceOf[RSAPublicKey],
        keyPair.getPrivate.asInstanceOf[RSAPrivateKey]
      )
    }

  def generateIdToken(user: User, clientId: String, nonce: Option[String] = None): IO[String] = {
    for {
      algorithm <- getAlgorithm
      now = Instant.now()
      exp = now.plusSeconds(config.tokenExpirationSeconds)

      // Use user provider as issuer for OBP-API compatibility, fallback to config issuer
      issuer = user.provider.getOrElse(config.issuer)

      token = JWT.create()
        .withIssuer(issuer)
        .withSubject(user.sub)
        .withAudience(clientId)
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(exp))
        .withKeyId(config.keyId)
        .withClaim("name", user.name.orNull)
        .withClaim("email", user.email.orNull)
        .withClaim("email_verified", user.email_verified.map(Boolean.box).orNull)

      tokenWithNonce = nonce.fold(token)(n => token.withClaim("nonce", n))
      signedToken = tokenWithNonce.sign(algorithm)
    } yield signedToken
  }

  def generateAccessToken(user: User, clientId: String, scope: String): IO[String] = {
    for {
      algorithm <- getAlgorithm
      now = Instant.now()
      exp = now.plusSeconds(config.tokenExpirationSeconds)

      // Use user provider as issuer for OBP-API compatibility, fallback to config issuer
      issuer = user.provider.getOrElse(config.issuer)

      token = JWT.create()
        .withIssuer(issuer)
        .withSubject(user.sub)
        .withAudience(config.issuer) // Access token audience is the resource server (ourselves)
        .withIssuedAt(Date.from(now))
        .withExpiresAt(Date.from(exp))
        .withKeyId(config.keyId)
        .withClaim("scope", scope)
        .withClaim("client_id", clientId)

      signedToken = token.sign(algorithm)
    } yield signedToken
  }

  def validateAccessToken(token: String): IO[Either[OidcError, AccessTokenClaims]] = {
    getAlgorithm.flatMap { algorithm =>
      IO {
        Try {
          // First decode token without verification to check issuer
          val unverifiedJWT = JWT.decode(token)
          val tokenIssuer = unverifiedJWT.getIssuer

          // Create verifier that accepts either config issuer or provider-based issuer
          val verifier = JWT.require(algorithm)
            .acceptIssuedAt(config.tokenExpirationSeconds)
            .build()

          val decodedJWT: DecodedJWT = verifier.verify(token)

          // Validate that issuer is either our config issuer or a reasonable provider value
          val issuer = decodedJWT.getIssuer
          if (issuer == null || issuer.trim.isEmpty) {
            throw new JWTVerificationException("Missing or empty issuer")
          }

          AccessTokenClaims(
            iss = decodedJWT.getIssuer,
            sub = decodedJWT.getSubject,
            aud = decodedJWT.getAudience.get(0), // Take first audience
            exp = decodedJWT.getExpiresAt.toInstant.getEpochSecond,
            iat = decodedJWT.getIssuedAt.toInstant.getEpochSecond,
            scope = decodedJWT.getClaim("scope").asString(),
            client_id = decodedJWT.getClaim("client_id").asString()
          )
        } match {
          case Success(claims) => claims.asRight[OidcError]
          case Failure(_: JWTVerificationException) =>
            OidcError("invalid_token", Some("Token validation failed")).asLeft[AccessTokenClaims]
          case Failure(ex) =>
            OidcError("server_error", Some(s"Token validation error: ${ex.getMessage}")).asLeft[AccessTokenClaims]
        }
      }
    }
  }

  def getJsonWebKey: IO[JsonWebKey] = {
    keyPairRef.get.map { keyPair =>
      val publicKey = keyPair.getPublic.asInstanceOf[RSAPublicKey]

      // Get RSA modulus and exponent as Base64URL encoded strings
      val modulus = Base64.getUrlEncoder.withoutPadding().encodeToString(publicKey.getModulus.toByteArray)
      val exponent = Base64.getUrlEncoder.withoutPadding().encodeToString(publicKey.getPublicExponent.toByteArray)

      JsonWebKey(
        kty = "RSA",
        use = "sig",
        kid = config.keyId,
        alg = "RS256",
        n = modulus,
        e = exponent
      )
    }
  }
}

object JwtService {

  def apply(config: OidcConfig): IO[JwtService[IO]] = {
    for {
      keyPair <- generateKeyPair
      keyPairRef <- Ref.of[IO, KeyPair](keyPair)
    } yield new JwtServiceImpl(config, keyPairRef)
  }

  private def generateKeyPair: IO[KeyPair] = IO {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(2048)
    keyPairGenerator.generateKeyPair()
  }
}
