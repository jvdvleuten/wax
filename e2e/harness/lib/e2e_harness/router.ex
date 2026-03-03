defmodule WaxE2EHarness.Router do
  use Plug.Router

  import Plug.Conn

  plug Plug.Logger

  plug Plug.Parsers,
    parsers: [:json],
    pass: ["application/json"],
    json_decoder: Jason

  plug :match
  plug :dispatch

  post "/reset" do
    WaxE2EHarness.Store.reset()
    json(conn, 200, %{ok: true})
  end

  get "/health" do
    send_resp(conn, 200, "ok")
  end

  get "/" do
    conn
    |> put_resp_content_type("text/html; charset=utf-8")
    |> send_resp(200, page_html())
  end

  post "/register/options" do
    origin = request_origin(conn)

    challenge =
      Wax.new_registration_challenge(
        origin: origin,
        rp_id: :auto,
        attestation: "none",
        user_verification: "preferred"
      )

    WaxE2EHarness.Store.put_registration_challenge(challenge)

    public_key_options = %{
      challenge: encode64url(challenge.bytes),
      rp: %{name: "Wax E2E Harness", id: challenge.rp_id},
      user: %{
        id: encode64url(:crypto.strong_rand_bytes(16)),
        name: "e2e@example.com",
        displayName: "E2E User"
      },
      pubKeyCredParams: [
        %{type: "public-key", alg: -7},
        %{type: "public-key", alg: -257}
      ],
      timeout: 60_000,
      attestation: "none"
    }

    json(conn, 200, %{publicKey: public_key_options})
  end

  post "/register/verify" do
    with %Wax.Challenge{} = challenge <- WaxE2EHarness.Store.get_registration_challenge(),
         {:ok, attestation_object} <- decode_base64url_from(conn.body_params, ["response", "attestationObject"]),
         {:ok, client_data_json} <- decode_base64url_from(conn.body_params, ["response", "clientDataJSON"]),
         {:ok, {authenticator_data, _attestation_result}} <-
           Wax.register(attestation_object, client_data_json, challenge) do
      credential = %{
        id: authenticator_data.attested_credential_data.credential_id,
        key: authenticator_data.attested_credential_data.credential_public_key,
        sign_count: authenticator_data.sign_count
      }

      WaxE2EHarness.Store.put_credential(credential)

      json(conn, 200, %{ok: true, credentialId: encode64url(credential.id)})
    else
      nil ->
        json(conn, 400, %{error: "No registration challenge is active"})

      {:error, {:missing_field, field_path}} ->
        json(conn, 400, %{error: "Missing required field: #{field_path}"})

      {:error, :invalid_base64url} ->
        json(conn, 400, %{error: "Invalid base64url payload"})

      {:error, %_{} = reason} ->
        json(conn, 422, %{error: Exception.message(reason)})

      {:error, reason} ->
        json(conn, 422, %{error: inspect(reason)})
    end
  end

  post "/authenticate/options" do
    with %{id: credential_id, key: credential_key} <- WaxE2EHarness.Store.get_credential() do
      origin = request_origin(conn)

      challenge =
        Wax.new_authentication_challenge(
          origin: origin,
          rp_id: :auto,
          allow_credentials: [{credential_id, credential_key}],
          user_verification: "preferred"
        )

      WaxE2EHarness.Store.put_authentication_challenge(challenge)

      public_key_options = %{
        challenge: encode64url(challenge.bytes),
        timeout: 60_000,
        userVerification: challenge.user_verification,
        allowCredentials: [
          %{type: "public-key", id: encode64url(credential_id)}
        ]
      }

      json(conn, 200, %{publicKey: public_key_options})
    else
      nil ->
        json(conn, 400, %{error: "No registered credential is available"})
    end
  end

  post "/authenticate/verify" do
    with %Wax.Challenge{} = challenge <- WaxE2EHarness.Store.get_authentication_challenge(),
         {:ok, raw_id} <- decode_base64url_from(conn.body_params, ["rawId"]),
         {:ok, authenticator_data} <- decode_base64url_from(conn.body_params, ["response", "authenticatorData"]),
         {:ok, signature} <- decode_base64url_from(conn.body_params, ["response", "signature"]),
         {:ok, client_data_json} <- decode_base64url_from(conn.body_params, ["response", "clientDataJSON"]),
         {:ok, auth_data} <-
           Wax.authenticate(raw_id, authenticator_data, signature, client_data_json, challenge) do
      WaxE2EHarness.Store.update_sign_count(auth_data.sign_count)

      json(conn, 200, %{ok: true, signCount: auth_data.sign_count})
    else
      nil ->
        json(conn, 400, %{error: "No authentication challenge is active"})

      {:error, {:missing_field, field_path}} ->
        json(conn, 400, %{error: "Missing required field: #{field_path}"})

      {:error, :invalid_base64url} ->
        json(conn, 400, %{error: "Invalid base64url payload"})

      {:error, %_{} = reason} ->
        json(conn, 422, %{error: Exception.message(reason)})

      {:error, reason} ->
        json(conn, 422, %{error: inspect(reason)})
    end
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp decode_base64url_from(params, path) do
    case get_in(params, path) do
      value when is_binary(value) ->
        case Base.url_decode64(value, padding: false) do
          {:ok, decoded} -> {:ok, decoded}
          :error -> {:error, :invalid_base64url}
        end

      _ ->
        {:error, {:missing_field, Enum.join(path, ".")}}
    end
  end

  defp encode64url(bytes) do
    Base.url_encode64(bytes, padding: false)
  end

  defp request_origin(conn) do
    port_part = if conn.port in [80, 443], do: "", else: ":#{conn.port}"
    "#{conn.scheme}://#{conn.host}#{port_part}"
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  defp page_html do
    """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Wax E2E Harness</title>
        <style>
          :root {
            font-family: "SF Pro Text", "Segoe UI", sans-serif;
            background: linear-gradient(160deg, #f6fbff, #eef3ff);
          }
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            color: #10233f;
          }
          main {
            width: min(640px, 92vw);
            background: #ffffff;
            border: 1px solid #d7e4f6;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(16, 35, 63, 0.08);
            padding: 28px;
          }
          h1 {
            margin: 0 0 8px;
            font-size: 1.5rem;
          }
          p {
            margin: 0 0 20px;
          }
          .actions {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
          }
          button {
            border: 0;
            border-radius: 10px;
            padding: 12px 14px;
            font-size: 0.95rem;
            cursor: pointer;
            background: #1e64d7;
            color: #fff;
          }
          button.secondary {
            background: #11449a;
          }
          pre {
            margin-top: 16px;
            padding: 12px;
            border-radius: 10px;
            background: #f4f8ff;
            border: 1px solid #dbe7fb;
            min-height: 56px;
            white-space: pre-wrap;
          }
          .error {
            color: #8b0013;
          }
        </style>
      </head>
      <body>
        <main>
          <h1>Wax Passkey E2E Harness</h1>
          <p>Use virtual authenticators to register and authenticate against Wax.</p>
          <div class="actions">
            <button data-testid="register-btn" id="register-btn">Register Passkey</button>
            <button class="secondary" data-testid="login-btn" id="login-btn">Login Passkey</button>
          </div>
          <pre data-testid="status" id="status">Ready</pre>
        </main>
        <script>
          const statusEl = document.getElementById("status");

          function setStatus(message, isError = false) {
            statusEl.textContent = message;
            statusEl.classList.toggle("error", isError);
          }

          function toBase64Url(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = "";
            bytes.forEach((b) => (binary += String.fromCharCode(b)));
            return btoa(binary).replace(/[+]/g, "-").replace(/[/]/g, "_").replace(/[=]+$/g, "");
          }

          function fromBase64Url(value) {
            const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
            const padded = base64 + "=".repeat((4 - (base64.length % 4 || 4)) % 4);
            const binary = atob(padded);
            const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
            return bytes.buffer;
          }

          async function request(path, payload) {
            const response = await fetch(path, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(payload || {})
            });

            const data = await response.json();

            if (!response.ok) {
              throw new Error(data.error || `HTTP ${response.status}`);
            }

            return data;
          }

          function normalizeRegistrationOptions(publicKey) {
            return {
              ...publicKey,
              challenge: fromBase64Url(publicKey.challenge),
              user: {
                ...publicKey.user,
                id: fromBase64Url(publicKey.user.id)
              }
            };
          }

          function normalizeAuthenticationOptions(publicKey) {
            return {
              ...publicKey,
              challenge: fromBase64Url(publicKey.challenge),
              allowCredentials: (publicKey.allowCredentials || []).map((credential) => ({
                ...credential,
                id: fromBase64Url(credential.id)
              }))
            };
          }

          async function registerPasskey() {
            setStatus("Creating credential...");

            const { publicKey } = await request("/register/options");
            const options = normalizeRegistrationOptions(publicKey);

            const credential = await navigator.credentials.create({ publicKey: options });

            await request("/register/verify", {
              rawId: toBase64Url(credential.rawId),
              response: {
                attestationObject: toBase64Url(credential.response.attestationObject),
                clientDataJSON: toBase64Url(credential.response.clientDataJSON)
              }
            });

            setStatus("Registration verified");
          }

          async function loginPasskey() {
            setStatus("Requesting assertion...");

            const { publicKey } = await request("/authenticate/options");
            const options = normalizeAuthenticationOptions(publicKey);

            const assertion = await navigator.credentials.get({ publicKey: options });

            const { signCount } = await request("/authenticate/verify", {
              rawId: toBase64Url(assertion.rawId),
              response: {
                authenticatorData: toBase64Url(assertion.response.authenticatorData),
                signature: toBase64Url(assertion.response.signature),
                clientDataJSON: toBase64Url(assertion.response.clientDataJSON)
              }
            });

            setStatus(`Authentication verified (signCount=${signCount})`);
          }

          document.getElementById("register-btn").addEventListener("click", async () => {
            try {
              await registerPasskey();
            } catch (error) {
              setStatus(`Registration failed: ${error.message}`, true);
            }
          });

          document.getElementById("login-btn").addEventListener("click", async () => {
            try {
              await loginPasskey();
            } catch (error) {
              setStatus(`Authentication failed: ${error.message}`, true);
            }
          });
        </script>
      </body>
    </html>
    """
  end
end
