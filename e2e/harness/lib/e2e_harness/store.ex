defmodule WaxE2EHarness.Store do
  use Agent

  @type credential :: %{
          id: binary(),
          key: map(),
          sign_count: non_neg_integer()
        }

  @type state :: %{
          registration_challenge: Wax.Challenge.t() | nil,
          authentication_challenge: Wax.Challenge.t() | nil,
          credential: credential() | nil
        }

  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(_opts) do
    Agent.start_link(fn -> initial_state() end, name: __MODULE__)
  end

  @spec reset() :: :ok
  def reset do
    Agent.update(__MODULE__, fn _ -> initial_state() end)
  end

  @spec get_registration_challenge() :: Wax.Challenge.t() | nil
  def get_registration_challenge do
    Agent.get(__MODULE__, & &1.registration_challenge)
  end

  @spec put_registration_challenge(Wax.Challenge.t()) :: :ok
  def put_registration_challenge(challenge) do
    Agent.update(__MODULE__, &Map.put(&1, :registration_challenge, challenge))
  end

  @spec get_authentication_challenge() :: Wax.Challenge.t() | nil
  def get_authentication_challenge do
    Agent.get(__MODULE__, & &1.authentication_challenge)
  end

  @spec put_authentication_challenge(Wax.Challenge.t()) :: :ok
  def put_authentication_challenge(challenge) do
    Agent.update(__MODULE__, &Map.put(&1, :authentication_challenge, challenge))
  end

  @spec get_credential() :: credential() | nil
  def get_credential do
    Agent.get(__MODULE__, & &1.credential)
  end

  @spec put_credential(credential()) :: :ok
  def put_credential(credential) do
    Agent.update(__MODULE__, &Map.put(&1, :credential, credential))
  end

  @spec update_sign_count(non_neg_integer()) :: :ok
  def update_sign_count(sign_count) do
    Agent.update(__MODULE__, fn state ->
      case state.credential do
        nil ->
          state

        credential ->
          Map.put(state, :credential, %{credential | sign_count: sign_count})
      end
    end)
  end

  @spec initial_state() :: state()
  defp initial_state do
    %{
      registration_challenge: nil,
      authentication_challenge: nil,
      credential: nil
    }
  end
end
