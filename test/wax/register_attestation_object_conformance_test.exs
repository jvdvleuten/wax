defmodule Wax.RegisterAttestationObjectConformanceTest do
  use ExUnit.Case, async: true
  @moduletag :conformance

  test "F-1 invalid CBOR map returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidCBORError{}} =
             Wax.register(<<1, 2, 3>>, client_data_json(challenge), challenge)
  end

  test "F-2 missing fmt field returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidCBORError{}} =
             Wax.register(
               attestation_object(%{
                 "attStmt" => %{},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-3 fmt is not a string returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidCBORError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => 123,
                 "attStmt" => %{},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-4 missing attStmt field returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidCBORError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-5 attStmt is not a map returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidCBORError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => "not-a-map",
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-6 missing authData field returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidCBORError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => %{}
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-7 authData not bytes returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidCBORError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => %{},
                 "authData" => %{"bad" => "type"}
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-8 empty authData returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidAuthenticatorDataError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => %{},
                 "authData" => <<>>
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-9 AT flag not set but attested credential data present returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidAuthenticatorDataError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => %{},
                 "authData" => registration_auth_data(challenge, 0x01, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-10 AT flag not set and attested credential data missing returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidAuthenticatorDataError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => %{},
                 "authData" => registration_auth_data(challenge, 0x01, :none)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-11 AT flag set but attested credential data missing returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidAuthenticatorDataError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => %{},
                 "authData" => registration_auth_data(challenge, 0x41, :none)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "F-12 attested credential data with leftover bytes returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.InvalidAuthenticatorDataError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "none",
                 "attStmt" => %{},
                 "authData" =>
                   registration_auth_data(challenge, 0x41, :valid_attested_data_with_leftover)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "unknown attestation format returns unsupported format error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.UnsupportedAttestationFormatError{}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "unknown-fmt",
                 "attStmt" => %{},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "packed self attestation empty map returns invalid CBOR error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.AttestationVerificationError{type: :packed, reason: :invalid_cbor}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "packed",
                 "attStmt" => %{},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "packed self attestation missing alg returns invalid CBOR error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.AttestationVerificationError{type: :packed, reason: :invalid_cbor}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "packed",
                 "attStmt" => %{"sig" => <<1, 2, 3>>},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "packed self attestation alg not number returns invalid CBOR error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.AttestationVerificationError{type: :packed, reason: :invalid_cbor}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "packed",
                 "attStmt" => %{"alg" => "not-a-number", "sig" => <<1, 2, 3>>},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "packed self attestation missing sig returns invalid CBOR error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.AttestationVerificationError{type: :packed, reason: :invalid_cbor}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "packed",
                 "attStmt" => %{"alg" => -7},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "packed self attestation sig not bytes returns invalid CBOR error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.AttestationVerificationError{type: :packed, reason: :invalid_cbor}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "packed",
                 "attStmt" => %{"alg" => -7, "sig" => 42},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "packed self attestation sig empty bytes returns invalid signature error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.AttestationVerificationError{type: :packed, reason: :invalid_signature}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "packed",
                 "attStmt" => %{"alg" => -7, "sig" => <<>>},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  test "packed self attestation alg mismatch returns error" do
    challenge = new_registration_challenge()

    assert {:error, %Wax.AttestationVerificationError{type: :packed, reason: :alg_mismatch}} =
             Wax.register(
               attestation_object(%{
                 "fmt" => "packed",
                 "attStmt" => %{"alg" => -257, "sig" => <<1, 2, 3>>},
                 "authData" => registration_auth_data(challenge, 0x41, :valid_attested_data)
               }),
               client_data_json(challenge),
               challenge
             )
  end

  defp new_registration_challenge do
    Wax.new_registration_challenge(
      origin: "https://example.com",
      rp_id: "example.com",
      attestation: "none"
    )
  end

  defp client_data_json(challenge) do
    %{
      "type" => "webauthn.create",
      "challenge" => Base.url_encode64(challenge.bytes, padding: false),
      "origin" => challenge.origin
    }
    |> Jason.encode!()
  end

  defp registration_auth_data(challenge, flags, data_kind) do
    rp_hash = :crypto.hash(:sha256, challenge.rp_id)
    header = rp_hash <> <<flags>> <> <<0::32>>

    case data_kind do
      :none ->
        header

      :valid_attested_data ->
        header <> valid_attested_credential_data()

      :valid_attested_data_with_leftover ->
        header <> valid_attested_credential_data() <> <<0, 1>>
    end
  end

  defp valid_attested_credential_data do
    aaguid = <<0::128>>
    credential_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

    cose_key =
      %{
        1 => 2,
        3 => -7,
        -1 => 1,
        -2 => :binary.copy(<<1>>, 32),
        -3 => :binary.copy(<<2>>, 32)
      }
      |> CBOR.encode()
      |> :erlang.iolist_to_binary()

    aaguid <> <<byte_size(credential_id)::16>> <> credential_id <> cose_key
  end

  defp attestation_object(map) do
    map
    |> CBOR.encode()
    |> :erlang.iolist_to_binary()
  end
end
