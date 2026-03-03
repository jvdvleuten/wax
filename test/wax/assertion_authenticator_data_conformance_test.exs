defmodule Wax.AssertionAuthenticatorDataConformanceTest do
  use ExUnit.Case, async: true
  @moduletag :conformance

  test "P-1 valid assertion succeeds for authenticator with signCount 0" do
    fixture = build_fixture(user_verification: "preferred", flags: 0x01, sign_count: 0)

    assert {:ok, %Wax.AuthenticatorData{sign_count: 0}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "P-2 valid assertion with UV set succeeds when userVerification is required" do
    fixture = build_fixture(user_verification: "required", flags: 0x05)

    assert {:ok, %Wax.AuthenticatorData{flag_user_verified: true}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "P-3 valid assertion with UV not set succeeds when userVerification is preferred" do
    fixture = build_fixture(user_verification: "preferred", flags: 0x01)

    assert {:ok, %Wax.AuthenticatorData{flag_user_verified: false}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "P-4 valid assertion with UV set succeeds when userVerification is preferred" do
    fixture = build_fixture(user_verification: "preferred", flags: 0x05)

    assert {:ok, %Wax.AuthenticatorData{flag_user_verified: true}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "P-5 valid assertion with UV not set succeeds when userVerification is discouraged" do
    fixture = build_fixture(user_verification: "discouraged", flags: 0x01)

    assert {:ok, %Wax.AuthenticatorData{flag_user_verified: false}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "P-6 valid assertion with UV set succeeds when userVerification is discouraged" do
    fixture = build_fixture(user_verification: "discouraged", flags: 0x05)

    assert {:ok, %Wax.AuthenticatorData{flag_user_verified: true}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "P-7 valid assertion with extension data succeeds when ED is set" do
    fixture =
      build_fixture(
        user_verification: "preferred",
        flags: 0x81,
        extensions: %{"example.extension" => "ok"}
      )

    assert {:ok,
            %Wax.AuthenticatorData{flag_extension_data_included: true, extensions: extensions}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )

    assert extensions["example.extension"] == "ok"
  end

  test "F-1 authenticatorData with leftover bytes returns an error" do
    fixture = build_fixture(user_verification: "preferred", flags: 0x01)

    assert {:error, %Wax.InvalidAuthenticatorDataError{}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data <> <<0>>,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "F-2 authenticatorData with invalid rpIdHash returns an error" do
    fixture = build_fixture(user_verification: "preferred", flags: 0x01)

    bad_auth_data =
      :crypto.hash(:sha256, "wrong.example.com") <> binary_part(fixture.auth_data, 32, 5)

    assert {:error, %Wax.InvalidClientDataError{reason: :rp_id_mismatch}} =
             Wax.authenticate(
               fixture.credential_id,
               bad_auth_data,
               <<0>>,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  test "F-3 assertion with signature over wrong clientDataHash returns invalid signature" do
    fixture = build_fixture(user_verification: "preferred", flags: 0x01)

    tampered_client_data_json =
      %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(fixture.challenge.bytes, padding: false),
        "origin" => fixture.challenge.origin,
        "tokenBinding" => %{"status" => "supported"}
      }
      |> Jason.encode!()

    assert {:error, %Wax.InvalidSignatureError{}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               tampered_client_data_json,
               fixture.challenge
             )
  end

  test "F-5 assertion with only UP set fails when userVerification is required" do
    fixture = build_fixture(user_verification: "required", flags: 0x01)

    assert {:error, %Wax.InvalidClientDataError{reason: :user_not_verified}} =
             Wax.authenticate(
               fixture.credential_id,
               fixture.auth_data,
               fixture.signature,
               fixture.client_data_json,
               fixture.challenge
             )
  end

  defp build_fixture(opts) do
    credential_id = Keyword.get(opts, :credential_id, "credential-assertion-1")
    user_verification = Keyword.get(opts, :user_verification, "preferred")
    flags = Keyword.get(opts, :flags, 0x01)
    sign_count = Keyword.get(opts, :sign_count, 0)
    extensions = Keyword.get(opts, :extensions)

    private_key = :public_key.generate_key({:namedCurve, :secp256r1})
    cose_key = cose_key_from_private(private_key)

    challenge =
      Wax.new_authentication_challenge(
        origin: "https://example.com",
        rp_id: "example.com",
        user_verification: user_verification,
        allow_credentials: [{credential_id, cose_key}]
      )

    auth_data = authenticator_data(challenge.rp_id, flags, sign_count, extensions)

    client_data_json =
      %{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(challenge.bytes, padding: false),
        "origin" => challenge.origin
      }
      |> Jason.encode!()

    client_data_hash = :crypto.hash(:sha256, client_data_json)
    signature = :public_key.sign(auth_data <> client_data_hash, :sha256, private_key)

    %{
      challenge: challenge,
      credential_id: credential_id,
      auth_data: auth_data,
      signature: signature,
      client_data_json: client_data_json
    }
  end

  defp authenticator_data(rp_id, flags, sign_count, nil) do
    :crypto.hash(:sha256, rp_id) <> <<flags>> <> <<sign_count::unsigned-big-integer-size(32)>>
  end

  defp authenticator_data(rp_id, flags, sign_count, extensions) do
    encoded_extensions =
      extensions
      |> CBOR.encode()
      |> :erlang.iolist_to_binary()

    authenticator_data(rp_id, flags, sign_count, nil) <> encoded_extensions
  end

  defp cose_key_from_private(
         {:ECPrivateKey, version, _private_key, params, public_key, :asn1_NOVALUE}
       )
       when version in [1, :ecPrivkeyVer1] do
    <<4, x::binary-size(32), y::binary-size(32)>> = public_key
    {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}} = params

    %{
      1 => 2,
      3 => -7,
      -1 => 1,
      -2 => x,
      -3 => y
    }
  end
end
