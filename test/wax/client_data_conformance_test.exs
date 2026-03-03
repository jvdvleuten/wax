defmodule Wax.ClientDataConformanceTest do
  use ExUnit.Case, async: true
  @moduletag :conformance

  @registration_cases [
    {"F-1 missing type", {:delete, "type"}},
    {"F-2 type not string", {:put, "type", 42}},
    {"F-3 type empty", {:put, "type", ""}},
    {"F-4 type not webauthn.create", {:put, "type", "potato"}},
    {"F-5 type set to webauthn.get", {:put, "type", "webauthn.get"}},
    {"F-6 missing challenge", {:delete, "challenge"}},
    {"F-7 challenge not string", {:put, "challenge", 42}},
    {"F-8 challenge empty", {:put, "challenge", ""}},
    {"F-9 challenge not base64url", {:put, "challenge", "%%%%"}},
    {"F-10 challenge not set to request.challenge", {:random_challenge, "challenge"}},
    {"F-11 missing origin", {:delete, "origin"}},
    {"F-12 origin not string", {:put, "origin", 42}},
    {"F-13 origin empty", {:put, "origin", ""}},
    {"F-14 origin mismatch", {:put, "origin", "https://evil.example.com"}},
    {"F-15 tokenBinding not object", {:put, "tokenBinding", 42}},
    {"F-16 tokenBinding missing status", {:put, "tokenBinding", %{}}},
    {"F-17 tokenBinding invalid status", {:put, "tokenBinding", %{"status" => "bananas"}}}
  ]

  @assertion_cases [
    {"F-1 missing type", {:delete, "type"}},
    {"F-2 type not string", {:put, "type", 42}},
    {"F-3 type empty", {:put, "type", ""}},
    {"F-4 type not webauthn.get", {:put, "type", "potato"}},
    {"F-5 type set to webauthn.create", {:put, "type", "webauthn.create"}},
    {"F-6 missing challenge", {:delete, "challenge"}},
    {"F-7 challenge not string", {:put, "challenge", 42}},
    {"F-8 challenge empty", {:put, "challenge", ""}},
    {"F-9 challenge not base64url", {:put, "challenge", "%%%%"}},
    {"F-10 challenge not set to request.challenge", {:random_challenge, "challenge"}},
    {"F-11 missing origin", {:delete, "origin"}},
    {"F-12 origin not string", {:put, "origin", 42}},
    {"F-13 origin empty", {:put, "origin", ""}},
    {"F-14 origin mismatch", {:put, "origin", "https://evil.example.com"}},
    {"F-15 tokenBinding not object", {:put, "tokenBinding", 42}},
    {"F-16 tokenBinding missing status", {:put, "tokenBinding", %{}}},
    {"F-17 tokenBinding invalid status", {:put, "tokenBinding", %{"status" => "bananas"}}}
  ]

  describe "ported from ServerAuthenticatorAttestationResponse CollectClientData negatives" do
    for {name, mutation} <- @registration_cases do
      test name do
        challenge = new_registration_challenge()

        client_data =
          mutate(base_client_data(challenge, "webauthn.create"), unquote(Macro.escape(mutation)))

        assert {:error, %Wax.InvalidClientDataError{}} =
                 Wax.register(
                   registration_attestation_object(challenge),
                   Jason.encode!(client_data),
                   challenge
                 )
      end
    end
  end

  describe "ported from ServerAuthenticatorAssertionResponse CollectClientData negatives" do
    for {name, mutation} <- @assertion_cases do
      test name do
        challenge = new_authentication_challenge()

        client_data =
          mutate(base_client_data(challenge, "webauthn.get"), unquote(Macro.escape(mutation)))

        assert {:error, %Wax.InvalidClientDataError{}} =
                 Wax.authenticate(
                   "credential-1",
                   authentication_data(challenge),
                   <<0>>,
                   Jason.encode!(client_data),
                   challenge
                 )
      end
    end
  end

  defp new_registration_challenge do
    Wax.new_registration_challenge(
      origin: "https://example.com",
      rp_id: "example.com",
      attestation: "none"
    )
  end

  defp new_authentication_challenge do
    Wax.new_authentication_challenge(
      origin: "https://example.com",
      rp_id: "example.com",
      allow_credentials: [{"credential-1", %{}}],
      user_verification: "preferred"
    )
  end

  defp base_client_data(challenge, type) do
    %{
      "type" => type,
      "challenge" => b64(challenge.bytes),
      "origin" => challenge.origin
    }
  end

  defp registration_attestation_object(challenge) do
    %{
      "fmt" => "none",
      "attStmt" => %{},
      "authData" => authentication_data(challenge)
    }
    |> CBOR.encode()
    |> :erlang.iolist_to_binary()
  end

  defp authentication_data(challenge) do
    :crypto.hash(:sha256, challenge.rp_id) <> <<0x01, 0, 0, 0, 0>>
  end

  defp mutate(data, {:delete, key}), do: Map.delete(data, key)
  defp mutate(data, {:put, key, value}), do: Map.put(data, key, value)

  defp mutate(data, {:random_challenge, key}) do
    Map.put(data, key, Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false))
  end

  defp b64(data), do: Base.url_encode64(data, padding: false)
end
