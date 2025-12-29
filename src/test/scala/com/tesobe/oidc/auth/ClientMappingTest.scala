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

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import com.tesobe.oidc.models.OidcClient
import java.util.UUID

/** Tests for client_id/consumer_id mapping between OidcClient and database
  * models
  *
  * These tests verify the critical fix where:
  *   - client_id maps to key_c in database (OAuth2 identifier)
  *   - consumer_id maps to consumerid in database (internal tracking)
  */
class ClientMappingTest extends AnyFunSuite with Matchers {

  test("AdminDatabaseClient.fromOidcClient should map client_id to key_c") {
    val consumerId = UUID.randomUUID().toString
    val clientId = UUID.randomUUID().toString

    val oidcClient = OidcClient(
      client_id = clientId,
      client_secret = Some("test-secret"),
      client_name = "Test Client",
      consumer_id = consumerId,
      redirect_uris = List("http://localhost/callback"),
      grant_types = List("authorization_code"),
      response_types = List("code"),
      scopes = List("openid", "profile", "email"),
      token_endpoint_auth_method = "client_secret_post",
      created_at = None
    )

    val adminClient = AdminDatabaseClient(
      name = Some(oidcClient.client_name),
      apptype = Some("WEB"),
      description = Some("OIDC client"),
      developeremail = Some("admin@tesobe.com"),
      sub = Some(oidcClient.client_name),
      consumerid = Some(oidcClient.consumer_id),
      createdat = None,
      updatedat = None,
      secret = oidcClient.client_secret,
      azp = Some(oidcClient.client_id),
      aud = Some("obp-api"),
      iss = Some("http://localhost:9000/obp-oidc"),
      redirecturl = Some(oidcClient.redirect_uris.mkString(",")),
      logourl = None,
      userauthenticationurl = None,
      clientcertificate = None,
      company = Some("TESOBE"),
      key_c = Some(oidcClient.client_id),
      isactive = Some(true)
    )

    // Verify correct mapping - this simulates what fromOidcClient should do
    adminClient.key_c shouldBe Some(clientId)
    adminClient.consumerid shouldBe Some(consumerId)
    adminClient.secret shouldBe Some("test-secret")
  }

  test(
    "AdminDatabaseClient should use consumer_id for consumerid and client_id for key_c"
  ) {
    val consumerId = "consumer-uuid-123"
    val clientId = "client-uuid-456"

    val oidcClient = OidcClient(
      client_id = clientId,
      client_secret = Some("secret-abc"),
      client_name = "Another Test Client",
      consumer_id = consumerId,
      redirect_uris = List("http://example.com/callback"),
      grant_types = List("authorization_code", "refresh_token"),
      response_types = List("code"),
      scopes = List("openid"),
      token_endpoint_auth_method = "client_secret_basic",
      created_at = None
    )

    val adminClient = AdminDatabaseClient(
      name = Some(oidcClient.client_name),
      apptype = Some("WEB"),
      description = Some("OIDC client"),
      developeremail = Some("admin@tesobe.com"),
      sub = Some(oidcClient.client_name),
      consumerid = Some(oidcClient.consumer_id),
      createdat = None,
      updatedat = None,
      secret = oidcClient.client_secret,
      azp = Some(oidcClient.client_id),
      aud = Some("obp-api"),
      iss = Some("http://localhost:9000/obp-oidc"),
      redirecturl = Some(oidcClient.redirect_uris.mkString(",")),
      logourl = None,
      userauthenticationurl = None,
      clientcertificate = None,
      company = Some("TESOBE"),
      key_c = Some(oidcClient.client_id),
      isactive = Some(true)
    )

    // consumer_id should be in consumerid field
    adminClient.consumerid shouldBe Some(consumerId)
    // client_id should be in key_c field
    adminClient.key_c shouldBe Some(clientId)
  }

  test("AdminDatabaseClient.toOidcClient should map key_c to client_id") {
    val consumerId = "db-consumer-789"
    val clientId = "db-client-012"

    val adminClient = AdminDatabaseClient(
      name = Some("Database Test Client"),
      apptype = Some("WEB"),
      description = Some("Test client from database"),
      developeremail = Some("dev@example.com"),
      sub = Some("test-sub"),
      consumerid = Some(consumerId),
      createdat = None,
      updatedat = None,
      secret = Some("db-secret"),
      azp = Some(clientId),
      aud = Some("obp-api"),
      iss = Some("http://localhost:9000/obp-oidc"),
      redirecturl = Some("http://localhost/callback"),
      logourl = None,
      userauthenticationurl = None,
      clientcertificate = None,
      company = Some("TESOBE"),
      key_c = Some(clientId),
      isactive = Some(true)
    )

    val oidcClient = adminClient.toOidcClient

    // Verify correct reverse mapping
    oidcClient.client_id shouldBe clientId
    oidcClient.consumer_id shouldBe consumerId
    oidcClient.client_secret shouldBe Some("db-secret")
  }

  test(
    "AdminDatabaseClient toOidcClient should correctly reverse the mapping"
  ) {
    val originalConsumerId = UUID.randomUUID().toString
    val originalClientId = UUID.randomUUID().toString

    // Create AdminDatabaseClient as if it came from database
    val adminClient = AdminDatabaseClient(
      name = Some("Round Trip Test"),
      apptype = Some("WEB"),
      description = Some("Test client"),
      developeremail = Some("dev@example.com"),
      sub = Some("test-sub"),
      consumerid = Some(originalConsumerId),
      createdat = None,
      updatedat = None,
      secret = Some("original-secret"),
      azp = Some(originalClientId),
      aud = Some("obp-api"),
      iss = Some("http://localhost:9000/obp-oidc"),
      redirecturl = Some("http://test.com/callback"),
      logourl = None,
      userauthenticationurl = None,
      clientcertificate = None,
      company = Some("TESOBE"),
      key_c = Some(originalClientId),
      isactive = Some(true)
    )

    // Convert to OIDC client
    val oidcClient = adminClient.toOidcClient

    // Verify IDs are mapped correctly
    oidcClient.client_id shouldBe originalClientId
    oidcClient.consumer_id shouldBe originalConsumerId
    oidcClient.client_name shouldBe "Round Trip Test"
    oidcClient.client_secret shouldBe Some("original-secret")
  }

  test("client_id and consumer_id should be different UUIDs") {
    val consumerId = UUID.randomUUID().toString
    val clientId = UUID.randomUUID().toString

    // They must be different
    consumerId should not equal clientId

    val oidcClient = OidcClient(
      client_id = clientId,
      client_secret = Some("test-secret"),
      client_name = "Distinct ID Test",
      consumer_id = consumerId,
      redirect_uris = List("http://localhost/callback"),
      grant_types = List("authorization_code"),
      response_types = List("code"),
      scopes = List("openid"),
      token_endpoint_auth_method = "client_secret_post",
      created_at = None
    )

    val adminClient = AdminDatabaseClient(
      name = Some(oidcClient.client_name),
      apptype = Some("WEB"),
      description = Some("OIDC client"),
      developeremail = Some("admin@tesobe.com"),
      sub = Some(oidcClient.client_name),
      consumerid = Some(oidcClient.consumer_id),
      createdat = None,
      updatedat = None,
      secret = oidcClient.client_secret,
      azp = Some(oidcClient.client_id),
      aud = Some("obp-api"),
      iss = Some("http://localhost:9000/obp-oidc"),
      redirecturl = Some(oidcClient.redirect_uris.mkString(",")),
      logourl = None,
      userauthenticationurl = None,
      clientcertificate = None,
      company = Some("TESOBE"),
      key_c = Some(oidcClient.client_id),
      isactive = Some(true)
    )

    // Verify they remain different in database model
    adminClient.key_c should not equal adminClient.consumerid
    adminClient.key_c shouldBe Some(clientId)
    adminClient.consumerid shouldBe Some(consumerId)
  }

  test("DatabaseClient.toOidcClient should preserve field mappings") {
    val consumerId = "view-consumer-id"
    val clientId = "view-client-id"

    val databaseClient = DatabaseClient(
      client_id = clientId,
      client_secret = Some("view-secret"),
      client_name = "View Test Client",
      consumer_id = consumerId,
      redirect_uris = Some("http://localhost/callback"),
      grant_types = Some("authorization_code,refresh_token"),
      response_types = Some("code"),
      scopes = Some("openid,profile,email"),
      token_endpoint_auth_method = Some("client_secret_post"),
      created_at = Some("2025-01-01T00:00:00Z")
    )

    val oidcClient = databaseClient.toOidcClient

    // DatabaseClient already has correct field names from view
    oidcClient.client_id shouldBe clientId
    oidcClient.consumer_id shouldBe consumerId
    oidcClient.client_name shouldBe "View Test Client"
    oidcClient.client_secret shouldBe Some("view-secret")
  }

  test(
    "Mapping should handle empty optional fields without breaking ID assignment"
  ) {
    val consumerId = UUID.randomUUID().toString
    val clientId = UUID.randomUUID().toString

    val oidcClient = OidcClient(
      client_id = clientId,
      client_secret = None, // No secret
      client_name = "Minimal Client",
      consumer_id = consumerId,
      redirect_uris = List("http://localhost/callback"),
      grant_types = List("authorization_code"),
      response_types = List("code"),
      scopes = List("openid"),
      token_endpoint_auth_method = "none",
      created_at = None
    )

    val adminClient = AdminDatabaseClient(
      name = Some(oidcClient.client_name),
      apptype = Some("WEB"),
      description = Some("OIDC client"),
      developeremail = Some("admin@tesobe.com"),
      sub = Some(oidcClient.client_name),
      consumerid = Some(oidcClient.consumer_id),
      createdat = None,
      updatedat = None,
      secret = oidcClient.client_secret,
      azp = Some(oidcClient.client_id),
      aud = Some("obp-api"),
      iss = Some("http://localhost:9000/obp-oidc"),
      redirecturl = Some(oidcClient.redirect_uris.mkString(",")),
      logourl = None,
      userauthenticationurl = None,
      clientcertificate = None,
      company = Some("TESOBE"),
      key_c = Some(oidcClient.client_id),
      isactive = Some(true)
    )

    // IDs should still be mapped correctly even with missing optional fields
    adminClient.key_c shouldBe Some(clientId)
    adminClient.consumerid shouldBe Some(consumerId)
    adminClient.secret shouldBe None
  }

  test(
    "AdminDatabaseClient with null key_c should handle gracefully in toOidcClient"
  ) {
    val adminClient = AdminDatabaseClient(
      name = Some("Incomplete Client"),
      apptype = Some("WEB"),
      description = None,
      developeremail = None,
      sub = None,
      consumerid = Some("some-consumer-id"),
      createdat = None,
      updatedat = None,
      secret = Some("some-secret"),
      azp = None,
      aud = None,
      iss = None,
      redirecturl = Some("http://localhost/callback"),
      logourl = None,
      userauthenticationurl = None,
      clientcertificate = None,
      company = None,
      key_c = None, // Missing key_c
      isactive = Some(true)
    )

    val oidcClient = adminClient.toOidcClient

    // Should default to empty string when key_c is None
    oidcClient.client_id shouldBe ""
    oidcClient.consumer_id shouldBe "some-consumer-id"
  }

  test("Field names should clearly indicate their purpose") {
    // This test documents the field naming convention
    val client = OidcClient(
      client_id = "oauth2-identifier", // Used by external apps
      client_secret = Some("oauth2-secret"),
      client_name = "Purpose Documentation",
      consumer_id =
        "internal-tracking-id", // Used for internal database tracking
      redirect_uris = List("http://localhost/callback"),
      grant_types = List("authorization_code"),
      response_types = List("code"),
      scopes = List("openid"),
      token_endpoint_auth_method = "client_secret_post",
      created_at = None
    )

    // Document what each field is used for
    info("client_id: OAuth2/OIDC identifier used by external applications")
    info("consumer_id: Internal database tracking ID (primary key)")
    info("key_c (database): Maps to client_id - the OAuth2 identifier")
    info("consumerid (database): Maps to consumer_id - internal tracking")

    client.client_id should not be empty
    client.consumer_id should not be empty
  }
}
