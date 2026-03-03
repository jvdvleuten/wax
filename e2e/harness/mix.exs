defmodule WaxE2EHarness.MixProject do
  use Mix.Project

  def project do
    [
      app: :wax_e2e_harness,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {WaxE2EHarness.Application, []}
    ]
  end

  defp deps do
    [
      {:wax_, path: "../.."},
      {:plug_cowboy, "~> 2.7"},
      {:jason, "~> 1.4"}
    ]
  end
end
