defmodule Mix.Tasks.E2e.Server do
  use Mix.Task

  @shortdoc "Starts the Wax browser E2E harness server"

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("app.start")

    {opts, _remaining, _invalid} =
      OptionParser.parse(args,
        strict: [host: :string, port: :integer]
      )

    host = Keyword.get(opts, :host, "127.0.0.1")
    port = Keyword.get(opts, :port, 4100)

    {:ok, _pid} =
      Plug.Cowboy.http(WaxE2EHarness.Router, [],
        ip: parse_host!(host),
        port: port
      )

    Mix.shell().info("Wax E2E harness listening on http://#{host}:#{port}")

    receive do
    end
  end

  defp parse_host!(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, ip} -> ip
      {:error, _} -> Mix.raise("Invalid --host value: #{host}")
    end
  end
end
