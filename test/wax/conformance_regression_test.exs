defmodule Wax.ConformanceRegressionTest do
  use ExUnit.Case, async: true
  @moduletag :conformance

  test "registration rejects attestation when user verification is required and UV is not set" do
    challenge =
      Wax.new_registration_challenge(
        origin: "https://example.com",
        rp_id: "example.com",
        attestation: "none",
        user_verification: "required"
      )

    auth_data =
      :crypto.hash(:sha256, challenge.rp_id) <>
        <<0x41, 0, 0, 0, 0>> <> valid_attested_credential_data()

    attestation_object =
      %{
        "fmt" => "none",
        "attStmt" => %{},
        "authData" => auth_data
      }
      |> CBOR.encode()
      |> :erlang.iolist_to_binary()

    assert {:error, %Wax.InvalidClientDataError{reason: :user_not_verified}} =
             Wax.register(attestation_object, client_data_json(:create, challenge), challenge)
  end

  test "authentication rejects assertion when user verification is required and UV is not set" do
    credential_id = "credential-1"

    challenge =
      Wax.new_authentication_challenge(
        origin: "https://example.com",
        rp_id: "example.com",
        user_verification: "required",
        allow_credentials: [{credential_id, %{}}]
      )

    auth_data = :crypto.hash(:sha256, challenge.rp_id) <> <<0x01, 0, 0, 0, 0>>

    assert {:error, %Wax.InvalidClientDataError{reason: :user_not_verified}} =
             Wax.authenticate(
               credential_id,
               auth_data,
               <<0>>,
               client_data_json(:get, challenge),
               challenge
             )
  end

  test "registration keeps backward-compatible reason for unexpected clientData type" do
    challenge =
      Wax.new_registration_challenge(
        origin: "https://example.com",
        rp_id: "example.com",
        attestation: "none",
        user_verification: "required"
      )

    auth_data =
      :crypto.hash(:sha256, challenge.rp_id) <>
        <<0x41, 0, 0, 0, 0>> <> valid_attested_credential_data()

    attestation_object =
      %{
        "fmt" => "none",
        "attStmt" => %{},
        "authData" => auth_data
      }
      |> CBOR.encode()
      |> :erlang.iolist_to_binary()

    invalid_type_client_data =
      %{
        "type" => "unexpected",
        "challenge" => Base.url_encode64(challenge.bytes, padding: false),
        "origin" => challenge.origin
      }
      |> Jason.encode!()

    assert {:error, %Wax.InvalidClientDataError{reason: :create_type_expected}} =
             Wax.register(attestation_object, invalid_type_client_data, challenge)
  end

  test "authentication keeps backward-compatible reason for unexpected clientData type" do
    credential_id = "credential-1"

    challenge =
      Wax.new_authentication_challenge(
        origin: "https://example.com",
        rp_id: "example.com",
        user_verification: "required",
        allow_credentials: [{credential_id, %{}}]
      )

    auth_data = :crypto.hash(:sha256, challenge.rp_id) <> <<0x01, 0, 0, 0, 0>>

    invalid_type_client_data =
      %{
        "type" => "unexpected",
        "challenge" => Base.url_encode64(challenge.bytes, padding: false),
        "origin" => challenge.origin
      }
      |> Jason.encode!()

    assert {:error, %Wax.InvalidClientDataError{reason: :get_type_expected}} =
             Wax.authenticate(credential_id, auth_data, <<0>>, invalid_type_client_data, challenge)
  end

  defp client_data_json(type, challenge) do
    type =
      case type do
        :create -> "webauthn.create"
        :get -> "webauthn.get"
      end

    %{
      "type" => type,
      "challenge" => Base.url_encode64(challenge.bytes, padding: false),
      "origin" => challenge.origin
    }
    |> Jason.encode!()
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
end
