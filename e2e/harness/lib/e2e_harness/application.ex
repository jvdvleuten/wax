defmodule WaxE2EHarness.Application do
  use Application

  @impl Application
  def start(_type, _args) do
    children = [
      {WaxE2EHarness.Store, []}
    ]

    Supervisor.start_link(children,
      strategy: :one_for_one,
      name: WaxE2EHarness.Supervisor
    )
  end
end
